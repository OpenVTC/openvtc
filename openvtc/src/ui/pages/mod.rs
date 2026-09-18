use crate::{
    state_handler::{
        actions::Action,
        state::{ActivePage, State},
    },
    ui::{
        component::{Component, ComponentRender},
        pages::{
            join_flow::JoinFlow, loading::LoadingScreen, main::MainPage, setup_flow::SetupFlow,
        },
    },
};
use crossterm::event::KeyEvent;
use ratatui::Frame;
use tokio::sync::mpsc::UnboundedSender;

pub mod create_persona_overlay;
pub mod join_flow;
pub mod loading;
pub mod main;
pub mod setup_flow;

struct Props {
    active_page: ActivePage,
    #[cfg(feature = "openpgp-card")]
    token_touch_pending: bool,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            active_page: state.active_page,
            #[cfg(feature = "openpgp-card")]
            token_touch_pending: state.token_touch_pending,
        }
    }
}

pub struct AppRouter {
    props: Props,
    //
    main_page: MainPage,
    setup_flow: SetupFlow,
    join_flow: JoinFlow,
    loading: LoadingScreen,
}

impl AppRouter {
    fn get_active_page_component_mut(&mut self) -> &mut dyn Component {
        match self.props.active_page {
            ActivePage::Loading => &mut self.loading,
            ActivePage::Main => &mut self.main_page,
            ActivePage::Setup => &mut self.setup_flow,
            ActivePage::Join => &mut self.join_flow,
        }
    }
}

impl Component for AppRouter {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        AppRouter {
            props: Props::from(state),
            //
            main_page: MainPage::new(state, action_tx.clone()),
            setup_flow: SetupFlow::new(state, action_tx.clone()),
            join_flow: JoinFlow::new(state, action_tx.clone()),
            loading: LoadingScreen::new(state, action_tx.clone()),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        AppRouter {
            props: Props::from(state),
            //
            main_page: self.main_page.move_with_state(state),
            setup_flow: self.setup_flow.move_with_state(state),
            join_flow: self.join_flow.move_with_state(state),
            loading: self.loading.move_with_state(state),
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        self.get_active_page_component_mut().handle_key_event(key)
    }

    fn handle_paste_event(&mut self, text: &str) {
        self.get_active_page_component_mut()
            .handle_paste_event(text)
    }
}

impl ComponentRender<()> for AppRouter {
    fn render(&self, frame: &mut Frame, props: ()) {
        match self.props.active_page {
            ActivePage::Loading => self.loading.render(frame, props),
            ActivePage::Main => self.main_page.render(frame, props),
            ActivePage::Setup => self.setup_flow.render(frame, props),
            ActivePage::Join => self.join_flow.render(frame, props),
        }

        #[cfg(feature = "openpgp-card")]
        if self.props.token_touch_pending {
            render_touch_overlay(frame);
        }
    }
}

/// Renders a centered popup overlay prompting the user to touch their hardware token.
#[cfg(feature = "openpgp-card")]
fn render_touch_overlay(frame: &mut Frame) {
    use crate::colors::{COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_TEXT_DEFAULT};
    use ratatui::{
        layout::{Constraint, Flex, Layout},
        style::Style,
        text::{Line, Span},
        widgets::{Block, Clear, Padding, Paragraph},
    };

    let area = frame.area();

    let popup_width = 50u16.min(area.width.saturating_sub(4));
    let popup_height = 7u16.min(area.height.saturating_sub(2));

    let [popup_area] = Layout::vertical([Constraint::Length(popup_height)])
        .flex(Flex::Center)
        .areas(area);
    let [popup_area] = Layout::horizontal([Constraint::Length(popup_width)])
        .flex(Flex::Center)
        .areas(popup_area);

    // Clear underlying content so the popup is readable
    frame.render_widget(Clear, popup_area);

    let block = Block::bordered()
        .title(" Hardware Token ")
        .title_style(Style::new().fg(COLOR_ORANGE).bold())
        .border_style(Style::new().fg(COLOR_ORANGE))
        .padding(Padding::uniform(1));

    let text = vec![
        Line::from(Span::styled(
            "Please touch your hardware token...",
            Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
        )),
        Line::default(),
        Line::from(Span::styled(
            "Waiting for physical confirmation",
            Style::new().fg(COLOR_DARK_GRAY),
        )),
    ];

    frame.render_widget(Paragraph::new(text).block(block), popup_area);
}
