/**
 * AWS KMS Node for Node-RED
 * 
 * This module provides AWS KMS operations (encrypt, decrypt, generateDataKey) for Node-RED.
 * It supports flexible credential handling through the aws-kms-config node.
 * 
 * @module node-red-contrib-aws-kms
 */

const {
    EncryptCommand,
    DecryptCommand,
    GenerateDataKeyCommand
} = require("@aws-sdk/client-kms");

module.exports = function(RED) {
    /**
     * AWS KMS Node constructor
     * 
     * @param {Object} config - Node configuration
     * @param {string} config.name - Node name
     * @param {string} config.awsConfig - AWS configuration node ID
     * @param {string} config.operation - KMS operation to perform
     * @param {string} config.keyId - KMS key ID
     * @param {string} config.keyIdType - Type of key ID input
     */
    function AWSKMSNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;
        const kmsConfig = RED.nodes.getNode(config.awsConfig);

        if (!kmsConfig) {
            node.error("AWS KMS configuration not found.");
            return;
        }

        // Store configuration
        this.operation = config.operation;
        this.keyId = config.keyId;
        this.keyIdType = config.keyIdType;

        /**
         * Get value from different input types
         * @param {string} value - Value to get
         * @param {string} type - Type of value (str, msg, flow, global, env)
         * @param {Object} msg - Message object
         * @returns {string} Retrieved value
         */
        function getValue(value, type, msg) {
            if (!value) return null;

            try {
                let result;
                switch (type) {
                    case 'msg':
                        result = RED.util.getMessageProperty(msg, value);
                        break;
                    case 'flow':
                        result = node.context().flow.get(value);
                        break;
                    case 'global':
                        result = node.context().global.get(value);
                        break;
                    case 'env':
                        result = process.env[value];
                        break;
                    default:
                        result = value;
                }
                return result;
            } catch (err) {
                throw new Error(`Failed to get value for type: ${type}, value: ${value}. Error: ${err.message}`);
            }
        }

        /**
         * Check if data is base64 encoded
         * @param {string} str - String to check
         * @returns {boolean} Whether the string is base64 encoded
         */
        function isBase64(str) {
            if (!str || typeof str !== 'string') return false;
            try {
                return Buffer.from(str, 'base64').toString('base64') === str;
            } catch (err) {
                return false;
            }
        }

        /**
         * Perform KMS encrypt operation
         * @param {Object} client - KMS client
         * @param {string} keyId - KMS key ID
         * @param {string|Buffer} plaintext - Data to encrypt
         * @returns {Promise<string>} Base64 encoded encrypted data
         */
        async function performEncrypt(client, keyId, plaintext) {
            let plaintextBuffer;
            
            if (Buffer.isBuffer(plaintext)) {
                plaintextBuffer = plaintext;
            } else if (typeof plaintext === 'string') {
                plaintextBuffer = Buffer.from(plaintext, 'utf8');
            } else {
                throw new Error("Plaintext must be a string or Buffer");
            }

            const command = new EncryptCommand({
                KeyId: keyId,
                Plaintext: plaintextBuffer
            });

            const response = await client.send(command);
            return Buffer.from(response.CiphertextBlob).toString('base64');
        }

        /**
         * Perform KMS decrypt operation
         * @param {Object} client - KMS client
         * @param {string} ciphertext - Base64 encoded encrypted data
         * @returns {Promise<string>} Decrypted plaintext
         */
        async function performDecrypt(client, ciphertext) {
            let ciphertextBuffer;
            
            if (typeof ciphertext === 'string') {
                if (isBase64(ciphertext)) {
                    ciphertextBuffer = Buffer.from(ciphertext, 'base64');
                } else {
                    throw new Error("Ciphertext string must be base64 encoded");
                }
            } else if (Buffer.isBuffer(ciphertext)) {
                ciphertextBuffer = ciphertext;
            } else {
                throw new Error("Ciphertext must be a base64 string or Buffer");
            }

            const command = new DecryptCommand({
                CiphertextBlob: ciphertextBuffer
            });

            const response = await client.send(command);
            return Buffer.from(response.Plaintext).toString('utf8');
        }

        /**
         * Perform KMS generate data key operation
         * @param {Object} client - KMS client
         * @param {string} keyId - KMS key ID
         * @param {string} keySpec - Key specification
         * @returns {Promise<Object>} Generated data key information
         */
        async function performGenerateDataKey(client, keyId, keySpec = 'AES_256') {
            const command = new GenerateDataKeyCommand({
                KeyId: keyId,
                KeySpec: keySpec
            });

            const response = await client.send(command);
            
            return {
                plaintextKey: Buffer.from(response.Plaintext).toString('base64'),
                encryptedKey: Buffer.from(response.CiphertextBlob).toString('base64'),
                keyId: response.KeyId
            };
        }

        // Handle incoming messages
        node.on('input', async (msg, send, done) => {
            try {
                // Get client with message context for credential resolution
                const client = kmsConfig.getClient(msg, node);
                
                if (!client) {
                    throw new Error("Failed to initialize KMS client");
                }

                // Get Key ID
                const keyId = getValue(node.keyId, node.keyIdType, msg);
                if (!keyId && (node.operation === 'encrypt' || node.operation === 'generateDataKey')) {
                    throw new Error("Key ID is required for encrypt and generateDataKey operations");
                }

                let result;

                switch (node.operation) {
                    case 'encrypt':
                        const plaintext = msg.payload.plaintext || msg.payload;
                        if (!plaintext) {
                            throw new Error("No plaintext data provided for encryption");
                        }
                        
                        result = await performEncrypt(client, keyId, plaintext);
                        msg.payload = {
                            ciphertext: result,
                            keyId: keyId
                        };
                        break;

                    case 'decrypt':
                        const ciphertext = msg.payload.ciphertext || msg.payload;
                        if (!ciphertext) {
                            throw new Error("No ciphertext data provided for decryption");
                        }
                        
                        result = await performDecrypt(client, ciphertext);
                        msg.payload = {
                            plaintext: result
                        };
                        break;

                    case 'generateDataKey':
                        const keySpec = msg.payload.keySpec || 'AES_256';
                        
                        result = await performGenerateDataKey(client, keyId, keySpec);
                        msg.payload = result;
                        break;

                    default:
                        throw new Error(`Unsupported operation: ${node.operation}`);
                }

                // Update node status
                node.status({ fill: "green", shape: "dot", text: `${node.operation} completed` });
                
                send(msg);
                done();

            } catch (err) {
                node.error(err.message, msg);
                node.status({ fill: "red", shape: "ring", text: err.message });
                
                // Send error in payload
                msg.payload = { error: err.message };
                send(msg);
                done();
            }
        });

        // Clear status on deploy
        node.status({});
    }

    // Register the node
    RED.nodes.registerType("aws-kms", AWSKMSNode);
}; 