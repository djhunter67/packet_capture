-- Create the interface table
CREATE TABLE IF NOT EXISTS interface (
    id SERIAL PRIMARY KEY, -- Automatically generated unique identifier
    interface VARCHAR(255) NOT NULL, -- Assuming the interface name will be a text string
    source_mac TEXT, -- Optional column for additional information
    destinatation_mac TEXT,
    source_port TEXT,
    destination_port TEXT,
    data_size NUMERIC, -- Assuming the data size will be a number
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Timestamp of when the record was created
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- Timestamp of last update
);

-- Add comments or descriptions if needed
COMMENT ON TABLE interface IS 'Table to store network interfaces.';
COMMENT ON COLUMN interface.interface_name IS 'The name of the network interface.';
COMMENT ON COLUMN interface.source_mac IS 'Source MAC address of the packet incoming to the network interface.';
