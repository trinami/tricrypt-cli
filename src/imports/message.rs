use sha3::{Sha3_256, Digest};

pub struct Message {
    pub length: u8,
    pub content: [u8; 111],
    pub iv: [u8; 16], // Add space for the IV
}

impl Message {
    pub fn new(content: &[u8]) -> Self {
        let mut message = Message {
            length: content.len().min(111) as u8,
            content: [0; 111],
            iv: [0; 16], // Initialize the IV
        };
        message.content[..message.length as usize].copy_from_slice(&content[..message.length as usize]);
        message
    }

    pub fn as_full_array(&self) -> [u8; 128] {
        let mut full_array = [0u8; 128];
        full_array[0] = self.length;
        full_array[1..112].copy_from_slice(&self.content);
        full_array[112..].copy_from_slice(&self.iv); // Include the IV
        full_array
    }

    pub fn set_from_full_array(&mut self, full_array: [u8; 128]) {
        self.length = full_array[0];
        self.content.copy_from_slice(&full_array[1..112]);
        self.iv.copy_from_slice(&full_array[112..]); // Set the IV
    }

    pub fn pad(&mut self) {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.content[..self.length as usize]);
        let mut hash = hasher.finalize_reset();

        let mut index = self.length as usize;
        while index < 111 {
            let len = (111 - index).min(hash.len());
            self.content[index..index + len].copy_from_slice(&hash[..len]);
            index += len;
            if index < 111 {
                hasher.update(&hash);
                hash = hasher.finalize_reset();
            }
        }
    }

    pub fn unpad(&mut self) {
        let length = self.length as usize;
        self.content[length..].fill(0);
    }
}