use std::fs;

use postgres::{Client, NoTls};

#[derive(Clone)]
pub struct Pool {
    pub connection_str: String,
}

impl Pool {
    pub fn new(url: &str, db_name: &str, username: &str, db_pw: &str) -> Self {
        Self {
            connection_str: format!("postgresql://{}:{}@{}/{}", username, db_pw, url, db_name,),
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

        println!("Reading the sql file");
        let init_script = match fs::read_to_string("init.sql") {
            Ok(script) => script,
            Err(err) => {
                println!("\n\n\tError reading init.sql: {err:?}\n\n");
                return Err(anyhow::Error::new(err));
            }
        };

        for stmt in init_script.split(";") {
            if !stmt.trim().is_empty() {
                match client.batch_execute(stmt) {
                    Ok(_) => {
                        // println!("Executed: {}", stmt);
                    }
                    Err(e) => {
                        println!("Error executing: {}", stmt);
                        return Err(anyhow::Error::new(e));
                    }
                }
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
