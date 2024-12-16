use crate::*;
// Change this later, but the warning is very annoying
#[allow(async_fn_in_trait)]
pub trait VaultManagement {
    async fn get_folders(
        self,
        vault_pool: SqlitePool,
        errors: Arc<Mutex<VecDeque<String>>>,
    ) -> Result<Vec<Folder>, u8>;
    async fn initialize_vault_files(
        self,
        master_passphrase: String,
        vault_pool: SqlitePool,
        errors: Arc<Mutex<VecDeque<String>>>,
    ) -> Result<u8, u8>;
    async fn login_to_vault(
        self,
        vault_pool: SqlitePool,
        errors: Arc<Mutex<VecDeque<String>>>,
    ) -> Result<(), u8>;
}

// TODO: Make functions more modular
// Database functions
impl VaultManagement for Arc<ApplicationAsyncState> {
    async fn get_folders(
        self,
        vault_pool: SqlitePool,
        error_notifications: Arc<Mutex<VecDeque<String>>>,
    ) -> Result<Vec<Folder>, u8> {
        let mut connection = vault_pool.acquire().await.expect_throw(
            error_notifications.clone(),
            "Unexpected Error: Could not fetch vault connection",
        )?;
        connection.close_on_drop();
        Ok::<Vec<Folder>, u8>(
            sqlx::query_as!(Folder, "SELECT * FROM Folders;")
                .fetch_all(connection.as_mut())
                .await
                .expect_throw(
                    error_notifications.clone(),
                    "Unexpected Error: Malformed Database, Could not fetch folders",
                )?,
        )
    }

    async fn initialize_vault_files(
        self,
        mut master_passphrase: String,
        vault_pool: SqlitePool,
        error_notifications: Arc<Mutex<VecDeque<String>>>,
    ) -> Result<u8, u8> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let salt = SaltString::generate(&mut OsRng);
        let mut output: Vec<u8>;
        let mut keyfile_contents;
        let mut output_key = [0u8; 32];
        let mut cipher;
        let mut connection;
        let mut keyfile = fs::File::create(
            self.app_directory
                .read()
                .unwrap()
                .directory_handler
                .data_local_dir()
                .join("main.keyfile"),
        )
        .expect_throw(
            error_notifications.clone(),
            "Failed to open the keyfile for writing",
        )?;

        keyfile_contents = KeyfileContents {
            hashed_password: String::default(),
            derivation_salt: salt.to_string(),
            nonce: nonce.to_vec(),
            encrypted_master_passphrase: Vec::new(),
        };

        // TODO: transfer this into the argon2_async library
        argon2_async::get_hasher()
            .await
            .unwrap()
            .hash_password_into_with_memory(
                self.master_password.read().unwrap().as_bytes(),
                keyfile_contents.derivation_salt.as_bytes(),
                &mut output_key,
                self.mem_block.lock().unwrap().deref_mut(),
            )
            .expect_throw(
                error_notifications.clone(),
                "Unexpected Error: failed to hash password",
            )?;

        // println!("Salt: {}", keyfile_contents.derivation_salt);
        // println!("{:?}", output_key);
        // for _ in 0..500000 {
        //     argon2
        //         .hash_password_into(
        //             &output_key.clone(),
        //             keyfile_contents.derivation_salt.as_bytes(),
        //             &mut output_key,
        //         )
        //         .expect("Unexpected Error: failed to hash password in loop");
        // }

        cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&output_key).expect_throw(
            error_notifications.clone(),
            "Unexpected Error: Failed to generate chacha20 key from slice",
        )?;

        keyfile_contents.encrypted_master_passphrase = chacha20poly1305::ChaChaPoly1305::encrypt(
            &mut cipher,
            &nonce,
            master_passphrase.as_bytes(),
        )
        .expect_throw(
            error_notifications.clone(),
            "Unexpected Error: could not encrypt payload",
        )?;

        keyfile_contents.hashed_password = argon2_async::hash(output_key).await.expect_throw(
            error_notifications.clone(),
            "Unexpected Error: could not hash password",
        )?;

        output = to_allocvec(&keyfile_contents).expect_throw(
            error_notifications.clone(),
            "Unexpected Error: Failed to serialize data",
        )?;

        keyfile
            .write_all(&output)
            .expect_throw(error_notifications.clone(), "Failed to write data to file")?;

        vault_pool.set_connect_options(
            // TODO: make this a macro or function for reproducability
            SqliteConnectOptions::new()
                .filename(
                    self.app_directory
                        .read()
                        .unwrap()
                        .directory_handler
                        .data_local_dir()
                        .join("main.db"),
                )
                .pragma("key", format!("'{}'", master_passphrase))
                .pragma("cipher_memory_security", "ON")
                .foreign_keys(true)
                .journal_mode(SqliteJournalMode::Off)
                .create_if_missing(true),
        );

        connection = vault_pool.acquire().await.expect_throw(
            error_notifications.clone(),
            "Unexpected Error (2): failed to open vault connection.",
        )?;

        sqlx::query!(
            "
            BEGIN;
            CREATE TABLE IF NOT EXISTS Folders ( folder_id INTEGER PRIMARY KEY AUTOINCREMENT, folder_name VARCHAR(255), folder_icon VARCHAR(255) );
            CREATE TABLE IF NOT EXISTS Entries ( entry_id INTEGER PRIMARY KEY AUTOINCREMENT, entry_name VARCHAR(255), entry_icon VARCHAR(255), is_deleted BOOLEAN DEFAULT FALSE);
            CREATE TABLE IF NOT EXISTS EntryTags (tag_id INTEGER PRIMARY KEY AUTOINCREMENT, tag_name VARCHAR(255), entry_id int);
            CREATE TABLE IF NOT EXISTS EntryData (data_id INTEGER PRIMARY KEY AUTOINCREMENT, section_name VARCHAR(255), section_type VARCHAR(255), section_data BLOB, entry_id int);
            COMMIT;
            "
        )
        .execute(connection.as_mut())
        .await
        .expect_throw(error_notifications.clone(), "Unexpected Error: could not setup database schema")?;

        sqlx::query!(
            "BEGIN;
            INSERT INTO Folders (folder_name, folder_icon) VALUES ('Online', 'default');
            INSERT INTO Entries (entry_name, entry_icon) VALUES ('Welcome', 'default');
            INSERT INTO EntryData (section_name, section_type, section_data, entry_id) VALUES ('Letter', 'blob', 'Thanks for using keylight!', 0);
            COMMIT;"
        )
        .execute(connection.as_mut())
        .await
        .expect_throw(error_notifications.clone(), "Unexpected Error: could not add initial entries to database")?;

        // self.vault_connection
        //     .as_mut()
        //     .unwrap()
        //     .pragma_update(None, "KEY", master_passphrase)
        //     .expect_throw(&mut self.error_notification.clone(), "Failed to set PRAGMA key")?;

        // self.vault_connection
        //     .as_mut()
        //     .unwrap()
        //     .pragma_update(None, "FOREIGN_KEYS", "ON")
        //     .expect_throw(&mut self.error_notification.clone(), "Failed to set PRAGMA Foreign keys to on")?;

        // self.vault_connection
        //     .as_mut()
        //     .unwrap()
        //     .execute_batch("
        //     BEGIN;
        // CREATE TABLE Folders ( folder_id INTEGER PRIMARY KEY AUTOINCREMENT, folder_name VARCHAR(255), folder_icon VARCHAR(255) );
        // CREATE TABLE Entries ( entry_id INTEGER PRIMARY KEY AUTOINCREMENT, entry_name VARCHAR(255), entry_icon VARCHAR(255), is_deleted BOOLEAN DEFAULT FALSE);
        // CREATE TABLE EntryTags (tag_id INTEGER PRIMARY KEY AUTOINCREMENT, tag_name VARCHAR(255), entry_id int);
        // CREATE TABLE EntryData (data_id INTEGER PRIMARY KEY AUTOINCREMENT, section_name VARCHAR(255), section_type VARCHAR(255), section_data BLOB, entry_id int);
        // INSERT INTO Folders (folder_name, folder_icon) VALUES ('Online', 'default');
        // INSERT INTO Entries (entry_name, entry_icon) VALUES ('Welcome', 'default');
        // INSERT INTO EntryData (section_name, section_type, section_data, entry_id) VALUES ('Letter', 'blob', 'Thanks for using keylight!', 0);
        // COMMIT;
        //     ")
        //     .expect_throw(&mut self.error_notification.clone(),"Failed to create the Database Schema")?;

        master_passphrase.zeroize();
        output.zeroize();
        Ok(0)
    }

    // There is a darn memory leak here, but I cannot find it
    // TODO: FIX MEMORY LEAK
    // It has something to do with the argon2 library
    async fn login_to_vault(
        self,
        vault_pool: SqlitePool,
        error_notifications: Arc<Mutex<VecDeque<String>>>,
    ) -> Result<(), u8> {
        let keyfile_contents: KeyfileContents;
        let mut cipher;
        let mut master_passphrase: String;
        let mut buffer: Vec<u8> = Vec::new();
        let mut output_key = [0u8; 32];
        let mut output_key_string: String;

        {
            let mut keyfile = fs::File::open(
                self.app_directory
                    .read()
                    .unwrap()
                    .directory_handler
                    .data_local_dir()
                    .join("main.keyfile"),
            )
            .expect_throw(
                error_notifications.clone(),
                "Unexpected Error: Failed to open the keyfile for reading",
            )?;

            keyfile.read_to_end(&mut buffer).expect_throw(
                error_notifications.clone(),
                "Unexpected Error: failed to read the keyfile into a buffer",
            )?;
        }

        {
            keyfile_contents = from_bytes(&buffer).expect("Unexpected Error: malformed keyfile");
            argon2_async::get_hasher()
                .await
                .unwrap()
                .hash_password_into_with_memory(
                    self.master_password.read().unwrap().as_bytes(),
                    keyfile_contents.derivation_salt.as_bytes(),
                    &mut output_key,
                    self.mem_block.lock().unwrap().deref_mut(),
                )
                .expect_throw(
                    error_notifications.clone(),
                    "Unexpected Error: could not derive key",
                )?;
        }

        // TODO: implement verify feature with argon2-async
        let out =
            argon2_async::verify_with_vec(output_key.to_vec(), keyfile_contents.hashed_password)
                .await
                .expect_throw(error_notifications.clone(), "Failed to verify password")?;

        if !out {
            let mut err = error_notifications.lock().unwrap();
            println!("wrong password");
            err.push_back("Wrong password".to_string());
            return Err(0);
        }

        cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&output_key).expect_throw(
            error_notifications.clone(),
            "Unexpected Error: Failed to generate chacha20 key from slice",
        )?;

        master_passphrase = String::from_utf8(
            chacha20poly1305::ChaChaPoly1305::decrypt(
                &mut cipher,
                XNonce::from_slice(&keyfile_contents.nonce),
                keyfile_contents.encrypted_master_passphrase.as_slice(),
            )
            .expect_throw(
                error_notifications.clone(),
                "Unexpected Error: could not decode ciphertext",
            )?,
        )
        .expect_throw(
            error_notifications.clone(),
            "Unexpected Error: Could not derive master passphrase from ciphertext",
        )?;

        {
            vault_pool.set_connect_options(
                SqliteConnectOptions::new()
                    .filename(
                        self.app_directory
                            .read()
                            .unwrap()
                            .directory_handler
                            .data_local_dir()
                            .join("main.db"),
                    )
                    .pragma("key", format!("'{}'", master_passphrase))
                    .pragma("cipher_memory_security", "ON")
                    .foreign_keys(true)
                    .journal_mode(SqliteJournalMode::Off)
                    .create_if_missing(true),
            );
        }

        // println!("{}", master_passphrase);
        // self.vault_pool.acquire();

        // self.vault_connection = Some(
        //     Connection::open(
        //         self.app_directory
        //             .directory_handler
        //             .data_local_dir()
        //             .join("main.db"),
        //     )
        //     .expect_throw(&mut self.error_notification.clone(), "Failed to initialize vault")?,
        // );

        // self.vault_connection
        //     .as_mut()
        //     .unwrap()
        //     .pragma_update(None, "key", &master_passphrase)
        //     .expect_throw(&mut self.error_notification.clone(), "Failed to set the PRAGMA key")?;
        master_passphrase.zeroize();
        buffer.zeroize();
        output_key.zeroize();
        Ok(())
    }
}
