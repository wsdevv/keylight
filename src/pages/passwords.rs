use crate::*;
use iced::widget::column;
impl Keylight {
    pub(crate) fn passwords_page(&self) -> Element<Message> {
        //let folders = block_on(self.get_folders());

        let pane_grid =
            PaneGrid::new(&self.panes, |_, state, _is_maximized| {
                pane_grid::Content::new(responsive(move |_size| {
                    let mut folders_col: Column<'_, Message> = column![];

                    for folder in self.async_state.display_folders.lock().unwrap().as_slice() {
                        folders_col =
                            folders_col.push(text(folder.folder_name.clone().unwrap_or(
                                "Unexpected Error: Folder does not have name".to_string(),
                            )));
                    }
                    

                    let folders_scrollable = scrollable(folders_col);
                    
                    
                    match state {
                        PaneState::Data => text!("Data!").into(),
                        PaneState::Entries => text!("Entries!").into(),
                        PaneState::Folders => column![folders_scrollable].into(),
                    }
                }))
            })
            .on_resize(10, Message::PaneResized);

        container(pane_grid).width(Fill).height(Fill).into()
    }
}
