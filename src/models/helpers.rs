use std::fs;

use postgres::{Client, NoTls};

#[derive(Clone)]
pub struct Pool {
    pub connection_str: String,
}

impl Pool {
    pub fn new(url: &str, db_name: &str, username: &str, db_pw: &str) -> Self {
        Self {
            connection_str: format!(
                "postgresql://{}:{}@{}:5432/{}",
                username, db_pw, url, db_name,
            ),
        }
    }

    pub fn init_db(&self) -> Result<Client, anyhow::Error> {
        println!("Connecting to the DB\n");
        let mut client = match Client::connect(&self.connection_str, NoTls) {
            Ok(client) => client,
            Err(e) => {
                println!("Error connecting to the DB: {:?}", e);
                return Err(anyhow::Error::new(e));
            }
        };
        println!("\nConnected to the DB\n");

        let init_script = fs::read_to_string("init.sql").unwrap();

        for stmt in init_script.split(";") {
            if !stmt.trim().is_empty() {
                client.batch_execute(stmt).unwrap();
            }
        }

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_string() {
        let pool = Pool::new("localhost", "test", "test", "test");
        assert_eq!(
            pool.connection_str,
            "postgresql://test:test@localhost:5432/test"
        );
    }

    #[test]
    fn test_connection_string_2() {
        let pool = Pool::new("test_url", "test_db_name", "test_username", "test_db_pw");

        assert_eq!(
            pool.connection_str,
            "postgresql://test_username:test_db_pw@test_url:5432/test_db_name"
        );
    }
}
