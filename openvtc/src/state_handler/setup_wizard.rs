#[cfg(feature = "openpgp-card")]
use crate::state_handler::setup_token_actions;
use crate::{
    Interrupted,
    state_handler::{
        SetupWizardExit, StateHandler,
        actions::Action,
        setup_sequence::{Completion, MessageType, SetupPage, config::ConfigExtension},
        setup_vta_actions,
        state::{ActivePage, State},
    },
};
use anyhow::Result;
use openvtc_core::config::Config;
use secrecy::SecretString;
use tokio::sync::{broadcast, mpsc::UnboundedReceiver};

impl StateHandler {
    pub(crate) async fn setup_wizard(
        &self,
        action_rx: &mut UnboundedReceiver<Action>,
        interrupt_rx: &mut broadcast::Receiver<Interrupted>,
        state: &mut State,
    ) -> Result<SetupWizardExit> {
        state.active_page = ActivePage::Setup;

        // Holder for the created config
        let mut config: Option<Config> = None;
        // The single admin VTA session: opened once at provisioning (after the
        // ephemeral→admin DID swap) and reused by every subsequent VTA step, so
        // the admin DID holds ONE mediator connection for the whole flow rather
        // than a fresh WebSocket per call (which churns the mediator's
        // one-socket-per-DID policy and drops in-flight responses). Shut down
        // once when the wizard exits (below).
        let mut admin_client: Option<vta_sdk::client::VtaClient> = None;
        // Wrapped so the admin session is torn down on EVERY exit — including a
        // `?` error out of a handler below — and never leaks (the LeakGuard).
        let exit: Result<SetupWizardExit> = async {
            Ok(loop {
            let _ = self.state_tx.send(state.clone());
            tokio::select! {
            Some(action) = action_rx.recv() => match action {
                Action::Exit => {
                     break SetupWizardExit::Interrupted(Interrupted::UserInt);
                },
                Action::UXError(interrupted) => {
                    break  SetupWizardExit::Interrupted(interrupted);
                },
                Action::ImportConfig(filename, import_unlock_passphrase, new_unlock_passphrase) => {
                    // Import a configuration backup
                    let import_unlock_passphrase = SecretString::new(import_unlock_passphrase.into());
                    let new_unlock_passphrase = SecretString::new(new_unlock_passphrase.into());
                    state.setup.active_page = SetupPage::ConfigImport;
                    match Config::import(
                        state, &self.state_tx,
                        &import_unlock_passphrase,
                        &new_unlock_passphrase,
                        &filename,
                        &self.profile,
                    ) {
                        Ok(()) => {
                            state.setup.config_import.completed = Completion::CompletedOK;
                            state.setup.config_import.messages.push(MessageType::Info("Configuration import completed successfully.".to_string()));
                        }
                        Err(e) => {
                            state.setup.config_import.messages.push(MessageType::Error(format!("Importing Config failed: {e}")));
                            state.setup.config_import.completed = Completion::CompletedFail;
                        }
                    }
                },
                Action::ActivateMainMenu => {
                    // Switch to Main Menu
                    state.active_page = ActivePage::Main;
                    state.main_page.menu_panel.selected = true;
                    state.main_page.content_panel.selected = false;

                    if let Some(cfg) = config {
                        break SetupWizardExit::Config(Box::new(cfg));
                    } else {
                        state.setup.final_page.messages.push(MessageType::Error("Setup Wizard completed but no configuration was created.".to_string()));
                    }
                },
                Action::SetProtection(protection, next_page) => {
                    state.setup.protection = protection;
                    state.setup.active_page = next_page;
                },
                Action::VtaSubmitDid(vta_did) => {
                    setup_vta_actions::handle_vta_submit_did(state, &self.state_tx, vta_did).await?;
                },
                Action::RecoverPlanContext => {
                    // Needs the live admin session, which only this loop holds.
                    // Read-only: the plan is built and shown, and nothing is
                    // written until the operator confirms (D5).
                    if let Some(client) = admin_client.as_ref() {
                        setup_vta_actions::handle_recover_plan_context(
                            state,
                            &self.state_tx,
                            client,
                        )
                        .await;
                    }
                },
                Action::VtaStartProvision { context_id, transport } => {
                    // Close any prior admin session before re-provisioning.
                    if let Some(c) = admin_client.take() {
                        c.shutdown().await;
                    }
                    // R15: provisioning is the one genuinely multi-step inline
                    // sequence in setup (resolve → connection-test → connect →
                    // authenticate), so it can block for many seconds against an
                    // unreachable VTA. Race it against the interrupt so Ctrl-C /
                    // Exit stay live; on interrupt the provisioning future is
                    // dropped (it has persisted nothing — no config exists until
                    // `create_account`, so a cancel here leaves no on-disk state)
                    // and we leave via the existing `Interrupted` exit path.
                    tokio::select! {
                        result = setup_vta_actions::handle_vta_start_provision(state, &self.state_tx, context_id, transport) => {
                            admin_client = result?;
                        }
                        Ok(interrupted) = interrupt_rx.recv() => {
                            break SetupWizardExit::Interrupted(interrupted);
                        }
                    }
                },
                #[cfg(feature = "openpgp-card")]
                Action::GetTokens => {
                    setup_token_actions::handle_get_tokens(state);
                },
                #[cfg(feature = "openpgp-card")]
                Action::SetAdminPin(token, admin_pin) => {
                    setup_token_actions::handle_set_admin_pin(state, token, admin_pin);
                },
                #[cfg(feature = "openpgp-card")]
                Action::FactoryReset(token) => {
                    setup_token_actions::handle_factory_reset(state, token).await;
                },
                #[cfg(feature = "openpgp-card")]
                Action::TokenWriteKeys(token) => {
                    setup_token_actions::handle_token_write_keys(state, &self.state_tx, token).await;
                },
                #[cfg(feature = "openpgp-card")]
                Action::SetTouchPolicy(token) => {
                    setup_token_actions::handle_set_touch_policy(state, &self.state_tx, token);
                },
                #[cfg(feature = "openpgp-card")]
                Action::SetTokenName(token, name) => {
                    setup_token_actions::handle_set_token_name(state, &self.state_tx, token, &name);
                },
                Action::SetupCompleted(_setup_flow) => {
                    state.setup.active_page = SetupPage::FinalPage;
                    state.setup.final_page.messages.push(MessageType::Info("Creating your account configuration...".to_string()));
                    state.setup.final_page.messages.push(MessageType::Info("Securing sensitive data for storage...".to_string()));
                    state.setup.final_page.messages.push(MessageType::Info("Your device may prompt for authentication to access OS secure storage.".to_string()));
                    let _ = self.state_tx.send(state.clone());
                    // R-A-5: setup now bootstraps a State-A account (VTA admin
                    // credential + top-level context, no persona/community). A
                    // persona is minted later by the State-B join flow.
                    match Config::create_account(&state.setup, &self.profile).await {
                        Ok(cfg) => {
                            state.setup.final_page.completed = Completion::CompletedOK;
                            state.setup.final_page.messages.push(MessageType::Info("Account setup completed successfully.".to_string()));
                            config = Some(cfg);
                        },
                        Err(e) => {
                            state.setup.final_page.completed = Completion::CompletedFail;
                            state.setup.final_page.messages.push(MessageType::Error(format!("Couldn't create OpenVTC account. Reason: {e}")));
                        }
                    }
                },
                _ => {}
            },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break SetupWizardExit::Interrupted(interrupted);
                }
            }
            })
        }
        .await;

        // Tear down the single admin VTA session now that setup is over (no-op
        // for the REST transport). This is the one place the wizard's session is
        // closed — every VTA step above reused it without opening its own.
        if let Some(c) = admin_client {
            c.shutdown().await;
        }

        exit
    }
}
