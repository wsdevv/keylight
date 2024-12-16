use crate::*;
use iced::widget::column;
// New Vault Page
impl Keylight {
    fn boxed_text(&self, prefix: &str, text: &str) -> Element<Message> {
        text!("{prefix} {text}")
            .height(Length::FillPortion(1))
            .align_y(Center)
            .into()
    }
    pub(crate) fn new_vault_page(&self) -> Element<Message> {
        // TODO: This is very ugly (UI-wise) make it prettier
        let vault_creation_state: Element<Message> = match self
            .async_state
            .vault_creation_state
            .load(std::sync::atomic::Ordering::Acquire)
        {
            0 => column![row![column![
                text!("Please input your master password..."),
                row![
                    text_input(
                        "Master Password",
                        self.async_state.master_password.read().unwrap().as_ref()
                    )
                    .on_input(Message::PasswordInput)
                    .on_submit(Message::NextVaultCreationState),
                    button("Next").on_press(Message::NextVaultCreationState)
                ]
                .spacing(5),
                text(
                    self.error_notification
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_default()
                )
                .color(Color::from_rgb(255., 0., 0.))
            ]
            .width(300)
            .spacing(5)]
            .height(Fill)
            .align_y(Center)]
            .spacing(5)
            .width(Fill)
            .align_x(Center)
            .into(),
            1 => column![row![column![
                text!("Please confirm your master password..."),
                text_input(
                    "Master Password",
                    self.async_state.master_password.read().unwrap().as_ref()
                )
                .secure(true),
                row![
                    text_input(
                        "Confirm Your Master Password",
                        &self
                            .async_state
                            .master_password_confirmation
                            .read()
                            .unwrap()
                    )
                    .secure(true)
                    .on_input(Message::PasswordVerificationInput)
                    .on_submit(Message::VerifyMasterPassword),
                    button("Back").on_press(Message::ResetVaultCreationState),
                    button("Next").on_press(Message::VerifyMasterPassword),
                ]
                .spacing(5),
                text(
                    self.error_notification
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_default()
                )
                .color(Color::from_rgb(255., 0., 0.))
            ]
            .width(300)
            .spacing(5)]
            .height(Fill)
            .align_y(Center)]
            .spacing(5)
            .width(Fill)
            .align_x(Center)
            .into(),
            2 => row![
                row![column![column![
                    text!("Write down this Master Sync Key somewhere safe (case sensitive)"),
                    text!("DO NOT STORE IT ON YOUR DEVICES"),
                    text_input(
                        "Master Password",
                        self.async_state.master_password.read().unwrap().as_ref()
                    )
                    .secure(true),
                    text_input(
                        "Confirm Your Master Password",
                        &self
                            .async_state
                            .master_password_confirmation
                            .read()
                            .unwrap()
                    )
                    .secure(true),
                    row![
                        button("Back").on_press(Message::DeincrementVaultCreationState),
                        button("Next").on_press(Message::NextVaultCreationState),
                    ]
                    .spacing(5),
                    text(
                        self.error_notification
                            .lock()
                            .unwrap()
                            .pop_front()
                            .unwrap_or_default()
                    )
                    .color(Color::from_rgb(255., 0., 0.))
                ]
                .spacing(5)
                .width(300)]
                .align_x(Center)
                .width(Fill)
                .spacing(5)]
                .width(Length::FillPortion(1))
                .height(Fill)
                .align_y(Center),
                row![
                    column![
                        self.boxed_text("1. ", &self.master_passphrase[0]),
                        self.boxed_text("5. ", &self.master_passphrase[4]),
                        self.boxed_text("9. ", &self.master_passphrase[8]),
                        self.boxed_text("13. ", &self.master_passphrase[12]),
                        self.boxed_text("17. ", &self.master_passphrase[16]),
                        self.boxed_text("21. ", &self.master_passphrase[20]),
                    ]
                    .width(Length::FillPortion(1)),
                    column![
                        self.boxed_text("2. ", &self.master_passphrase[1]),
                        self.boxed_text("6. ", &self.master_passphrase[5]),
                        self.boxed_text("10. ", &self.master_passphrase[9]),
                        self.boxed_text("14. ", &self.master_passphrase[13]),
                        self.boxed_text("18. ", &self.master_passphrase[17]),
                        self.boxed_text("22. ", &self.master_passphrase[21]),
                    ]
                    .width(Length::FillPortion(1)),
                    column![
                        self.boxed_text("3. ", &self.master_passphrase[2]),
                        self.boxed_text("7. ", &self.master_passphrase[6]),
                        self.boxed_text("11. ", &self.master_passphrase[10]),
                        self.boxed_text("15. ", &self.master_passphrase[14]),
                        self.boxed_text("19. ", &self.master_passphrase[18]),
                        self.boxed_text("23. ", &self.master_passphrase[22]),
                    ]
                    .width(Length::FillPortion(1)),
                    column![
                        self.boxed_text("4. ", &self.master_passphrase[3]),
                        self.boxed_text("8. ", &self.master_passphrase[7]),
                        self.boxed_text("12. ", &self.master_passphrase[11]),
                        self.boxed_text("16. ", &self.master_passphrase[15]),
                        self.boxed_text("20. ", &self.master_passphrase[19]),
                        self.boxed_text("24. ", &self.master_passphrase[23]),
                    ]
                    .width(Length::FillPortion(1))
                ]
                .width(Length::FillPortion(1))
                .padding(10)
            ]
            .width(Fill)
            .height(Fill)
            .into(),
            //TODO: make this a more advanced/stylized loading screen
            3 => column![text!("Loading...")].into(),
            _ => column![
                text!("Unexpected Error: vault creation state incremented too large"),
                button("Go back").on_press(Message::ResetVaultCreationState)
            ]
            .into(),
        };

        container(vault_creation_state)
            .width(Fill)
            .height(Fill)
            .into()
    }
}
