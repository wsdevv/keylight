use std::alloc::{dealloc, Layout};
use std::borrow::BorrowMut;
use std::cell::LazyCell;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, LazyLock, Mutex, RwLock, RwLockReadGuard};
use std::time::Instant;
use std::{fs, path};

use argon2::password_hash::{rand_core::OsRng, PasswordHasher};
use argon2::password_hash::{Salt, SaltString};
use argon2::{Argon2, Block, PasswordHash, PasswordVerifier};
use chacha20poly1305::ChaChaPoly1305;
use chacha20poly1305::{aead::Aead, AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use chbs::config::BasicConfig;
use chbs::probability::Probability;
use chbs::scheme::ToScheme;
use directories::ProjectDirs;
use futures::TryFutureExt;
use iced::alignment::Horizontal::Left;
use iced::widget::pane_grid::{self, PaneGrid};
use iced::widget::{
    button, container, responsive, row, scrollable, text, text_input, toggler, Button, Column,
    TextInput,
};
use iced::{Center, Color, Element, Fill};
use iced::{Length, Padding, Task};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::SqlitePool;
use tokio::task::block_in_place;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[path = "./pages/login.rs"]
mod login_page;
#[path = "./pages/new_vault.rs"]
mod new_vault_page;
#[path = "./pages/passwords.rs"]
mod password_page;
#[path = "./lib/vault.rs"]
mod vault;
use vault::*;

#[tokio::main]
async fn main() -> iced::Result {
    argon2_async::set_config(argon2_async::Config::default()).await;
    block_in_place(|| {
        iced::application("Keylight", Keylight::update, Keylight::view)
            .theme(|_| iced::Theme::Dark)
            .antialiasing(true)
            .run()
    })
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Folder {
    folder_id: i64,
    folder_name: Option<String>,
    folder_icon: Option<String>,
}

#[derive(Debug, Clone)]
enum Message {
    PasswordInput(String),
    PasswordVerificationInput(String),
    ToggleGoogleDrive(bool),
    ToggleOneDrive(bool),
    ToggleDropBox(bool),
    PaneResized(pane_grid::ResizeEvent),
    NewVault,
    ImportVault,
    NextVaultCreationState,
    DeincrementVaultCreationState,
    ResetVaultCreationState,
    VerifyMasterPassword,
    LogIn,
    ManualUpdate,
}

enum Page {
    LogIn,
    Passwords,
    NewVault,
}

#[derive(Clone, Copy)]
enum PaneState {
    Folders,
    Entries,
    Data,
}

#[derive(Serialize, Deserialize)]
struct KeyfileContents {
    hashed_password: String,
    derivation_salt: String,
    nonce: Vec<u8>,
    encrypted_master_passphrase: Vec<u8>,
}

struct SyncServices {
    google_drive_enabled: bool,
    onedrive_enabled: bool,
    dropbox_enabled: bool,
}

struct StorageServices {
    directory_handler: ProjectDirs,
    main_db_exists: bool,
}

struct ApplicationAsyncState {
    master_password: RwLock<String>,
    master_password_confirmation: RwLock<String>,
    app_directory: RwLock<StorageServices>,
    page: Mutex<Page>,
    mem_block: Mutex<Vec<argon2::Block>>,
    display_folders: Mutex<Vec<Folder>>,
    vault_creation_state: AtomicU8,
}

// TODO: Modify Zeroize library to be able to zeroize all of these contents
struct Keylight {
    panes: pane_grid::State<PaneState>,
    vault_pool: SqlitePool,
    master_passphrase: Vec<String>,
    folder_id_picked: i64,
    application_loading: bool,
    sync_services: SyncServices,
    async_state: Arc<ApplicationAsyncState>,
    error_notification: Arc<Mutex<VecDeque<String>>>,
}

impl Keylight {
    fn new() -> Self {
        let directory_handler =
            ProjectDirs::from("dev", "Schell", "Keylight").expect("Operating System Unsupported");
        let path = path::Path::new(directory_handler.data_local_dir());
        let main_db_exists = path.join("main.db").exists();
        let (mut panes, pane) = pane_grid::State::new(PaneState::Folders);

        panes.split(pane_grid::Axis::Vertical, pane, PaneState::Data);
        panes.split(pane_grid::Axis::Vertical, pane, PaneState::Entries);

        if !path.exists() {
            fs::create_dir_all(path)
                .expect("Unexpected error, failed to create the application data directory");
        }

        Self {
            panes,
            master_passphrase: Vec::new(),
            folder_id_picked: 0,
            error_notification: Arc::new(Mutex::new(VecDeque::new())),
            application_loading: false,
            vault_pool: SqlitePool::connect_lazy(
                directory_handler
                    .data_local_dir()
                    .join("main.db")
                    .to_str()
                    .expect("Unexpected Error: Could not convert app directory to string"),
            )
            .expect("Unexpected Error: failed to access db"),
            async_state: Arc::new(ApplicationAsyncState {
                master_password: RwLock::new(String::default()),
                master_password_confirmation: RwLock::new(String::default()),
                page: Mutex::new(Page::LogIn),
                display_folders: Mutex::new(Vec::new()),
                mem_block: Mutex::new(vec![
                    Block::default();
                    Argon2::default().params().block_count()
                ]),
                app_directory: RwLock::new(StorageServices {
                    directory_handler,
                    main_db_exists,
                }),
                vault_creation_state: AtomicU8::new(0),
            }),
            sync_services: SyncServices {
                google_drive_enabled: false,
                onedrive_enabled: false,
                dropbox_enabled: false,
            },
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::LogIn => {
                self.application_loading = true;
                let vault_pool1 = self.vault_pool.clone();
                let vault_pool2 = self.vault_pool.clone();
                let state1 = self.async_state.clone();
                let state2 = self.async_state.clone();
                let state3 = self.async_state.clone();
                let err1 = self.error_notification.clone();
                let err2 = self.error_notification.clone();

                // TODO: add a loading bar
                Task::perform(
                    state1
                        .login_to_vault(vault_pool1, err1)
                        .and_then(|_| async move {
                            Ok::<Vec<Folder>, u8>(state2.get_folders(vault_pool2, err2).await?)
                        })
                        .and_then(|folders| async move {
                            *state3.page.lock().unwrap() = Page::Passwords;
                            let mut folders_access = state3.display_folders.lock().unwrap();
                            (*folders_access).zeroize();
                            *folders_access = folders;
                            Ok(())
                        }),
                    |_| Message::ManualUpdate,
                )
            }
            Message::NewVault => {
                *self.async_state.page.lock().unwrap() = Page::NewVault;
                Task::none()
            }
            Message::PasswordInput(input) => {
                let mut write = self.async_state.master_password.write().unwrap();
                (*write).zeroize();
                *write = input;
                Task::none()
            }

            // Vault Creation Page functions
            Message::PasswordVerificationInput(input) => {
                let mut write = self
                    .async_state
                    .master_password_confirmation
                    .write()
                    .unwrap();
                (*write).zeroize();
                *write = input;
                Task::none()
            }
            Message::NextVaultCreationState => {
                if self.async_state.master_password.read().unwrap().len() < 16 {
                    let mut error_notification = self.error_notification.lock().unwrap();
                    error_notification.push_back(
                        "Please make your Master password at least 16 characters long".to_string(),
                    );
                } else {
                    println!("[INFO]: Incremented vault creation state");
                    self.async_state
                        .vault_creation_state
                        .fetch_add(1, std::sync::atomic::Ordering::Release);
                }

                if self
                    .async_state
                    .vault_creation_state
                    .load(std::sync::atomic::Ordering::Acquire)
                    == 1
                {
                    let mut config = BasicConfig::default();
                    config.words = 24;
                    config.capitalize_first = Probability::half();
                    config.capitalize_words = Probability::Sometimes(0.2);
                    config.separator = " ".to_string();
                    let scheme = config.to_scheme();
                    self.master_passphrase = scheme
                        .generate()
                        .split_whitespace()
                        .map(|st| st.to_string())
                        .collect();
                    println!("[INFO]: Successfully generated master passphrase")
                } else if self
                    .async_state
                    .vault_creation_state
                    .load(std::sync::atomic::Ordering::Acquire)
                    > 2
                {
                    let vault_pool1 = self.vault_pool.clone();
                    let vault_pool2 = self.vault_pool.clone();
                    let state1 = self.async_state.clone();
                    let state2 = self.async_state.clone();
                    let state3 = self.async_state.clone();
                    let state4 = self.async_state.clone();
                    let err1 = self.error_notification.clone();
                    let err2 = self.error_notification.clone();

                    // TODO: implement a progress bar
                    return Task::perform(
                        state1
                            .clone()
                            .initialize_vault_files(
                                self.master_passphrase.join("~"),
                                vault_pool1,
                                err1,
                            )
                            .and_then(|_| async move {
                                state2
                                    .vault_creation_state
                                    .store(0, std::sync::atomic::Ordering::Release);
                                println!("[INFO]: Successfully transitioned to password page");
                                *state2.page.lock().unwrap() = Page::Passwords;
                                Ok(())
                            })
                            .and_then(|_| async move {
                                state4.get_folders(vault_pool2, err2).await?;
                                println!("[INFO]: Successfully fetched folders to password page");
                                Ok(())
                            })
                            // TODO: change UiRecovery to "String" errors to return correct errors
                            .or_else(|_| async move {
                                state3
                                    .vault_creation_state
                                    .fetch_sub(1, std::sync::atomic::Ordering::Release);
                                println!("[ERROR]: Vault creation state thwarted");
                                Ok::<(), ()>(())
                            }),
                        // TODO Return a better result
                        |_| Message::ManualUpdate,
                    );
                }
                Task::none()
            }
            Message::DeincrementVaultCreationState => {
                println!("[INFO]: Decremented Vault Creation State");
                self.async_state
                    .vault_creation_state
                    .fetch_sub(1, std::sync::atomic::Ordering::Release);
                Task::none()
            }
            Message::ResetVaultCreationState => {
                println!("[INFO]: Reset Vault Creation State");
                self.async_state
                    .vault_creation_state
                    .store(0, std::sync::atomic::Ordering::Release);
                self.async_state
                    .master_password_confirmation
                    .write()
                    .unwrap()
                    .clear();
                Task::none()
            }
            Message::VerifyMasterPassword => {
                if self.async_state.master_password.read().unwrap().as_str()
                    == self
                        .async_state
                        .master_password_confirmation
                        .read()
                        .unwrap()
                        .as_str()
                {
                    println!("[INFO]: Verified  master password");
                    self.async_state
                        .vault_creation_state
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                } else {
                    self.error_notification
                        .lock()
                        .unwrap()
                        .push_back("Passwords do not match".to_string());
                }

                Task::none()
            }

            // Sync Service Toggles
            Message::ToggleDropBox(toggler) => {
                self.sync_services.dropbox_enabled = toggler;
                Task::none()
            }
            Message::ToggleOneDrive(toggler) => {
                self.sync_services.onedrive_enabled = toggler;
                Task::none()
            }
            Message::ToggleGoogleDrive(toggler) => {
                self.sync_services.google_drive_enabled = toggler;
                Task::none()
            }

            // Misc
            Message::PaneResized(resize) => {
                self.panes.resize(resize.split, resize.ratio);
                Task::none()
            }

            Message::ManualUpdate => {
                self.application_loading = false;
                Task::none()
            }

            _ => Task::none(),
        }
    }

    fn view(&self) -> Element<'_, Message> {
        match *self.async_state.page.lock().unwrap() {
            Page::LogIn => self.login_page(),
            Page::Passwords => self.passwords_page(),
            Page::NewVault => self.new_vault_page(),
            _ => self.login_page(),
        }
    }
}

pub trait UiRecovery<T> {
    fn expect_throw(
        self,
        send_to: Arc<Mutex<VecDeque<String>>>,
        message: &'static str,
    ) -> Result<T, u8>;
}

impl<T, E: std::fmt::Debug> UiRecovery<T> for Result<T, E> {
    fn expect_throw(
        self,
        send_to: Arc<Mutex<VecDeque<String>>>,
        message: &'static str,
    ) -> Result<T, u8> {
        if self.is_ok() {
            drop(send_to);
            return Ok(self.ok().unwrap());
        } else {
            send_to.lock().unwrap().push_back(message.to_string());
            println!("[ERROR]: {:?}", self.err().unwrap());
            drop(send_to);
            return Err(0);
        }
    }
}

impl<T> UiRecovery<T> for Option<T> {
    fn expect_throw(
        self,
        send_to: Arc<Mutex<VecDeque<String>>>,
        message: &'static str,
    ) -> Result<T, u8> {
        if self.is_some() {
            drop(send_to);
            return Ok(self.unwrap());
        } else {
            send_to.lock().unwrap().push_back(message.to_string());
            println!("[ERROR]: Failed to unwrap None type");
            drop(send_to);
            return Err(0);
        }
    }
}

impl Default for Keylight {
    fn default() -> Self {
        Keylight::new()
    }
}

impl Zeroize for ApplicationAsyncState {
    fn zeroize(&mut self) {
        self.master_password.write().unwrap().zeroize();
        self.master_password_confirmation.write().unwrap().zeroize();
        self.mem_block.lock().unwrap().zeroize();
        self.display_folders.lock().unwrap().zeroize();
    }
}

impl Drop for ApplicationAsyncState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Drop for Keylight {
    fn drop(&mut self) {
        self.master_passphrase.zeroize();
    }
}
