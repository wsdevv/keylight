use crate::*;
use iced::widget::column;
impl Keylight {
    pub(crate) fn login_page(&self) -> Element<Message> {
        let mut password_input: TextInput<Message> = text_input(
            "Master Password",
            &self.async_state.master_password.read().unwrap(),
        )
        .width(150)
        .secure(true);
        let mut login_button: Button<Message> = button("Enter").width(100);

        if !self.application_loading {
            password_input = password_input
                .on_input(Message::PasswordInput)
                .on_submit(Message::LogIn);
            login_button = login_button.on_press(Message::LogIn);
        }

        let database_options = if self
            .async_state
            .app_directory
            .read()
            .unwrap()
            .main_db_exists
        {
            row![password_input, login_button,].spacing(5)
        } else {
            row![
                button("New Database")
                    .width(150)
                    .on_press(Message::NewVault),
                button("Import Database").width(150),
            ]
            .spacing(5)
        };

        container(
            column![
                row![text!("Keylight").size(50)],
                column![
                    database_options,
                    toggler(self.sync_services.google_drive_enabled)
                        .label("Google Drive")
                        .on_toggle(Message::ToggleGoogleDrive),
                    toggler(self.sync_services.onedrive_enabled)
                        .label("OneDrive")
                        .on_toggle(Message::ToggleOneDrive),
                    toggler(self.sync_services.dropbox_enabled)
                        .label("DropBox")
                        .on_toggle(Message::ToggleDropBox)
                ]
                .align_x(Left)
                .spacing(5),
                text(
                    self.error_notification
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_default()
                )
                .color(Color::from_rgb8(255, 0, 0)),
            ]
            .padding(Padding::from([0, 70]))
            .spacing(20)
            .width(Fill)
            .align_x(Center),
        )
        .center_y(Fill)
        .width(Fill)
        .height(Fill)
        .into()
    }
}
