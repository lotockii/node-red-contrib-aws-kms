/**
 * AWS KMS Node-RED Node
 * 
 * This module provides AWS KMS encryption, decryption, and key generation capabilities
 * for Node-RED flows. It supports both IAM roles and access key authentication.
 * 
 * @module node-red-contrib-aws-kms
 */

module.exports = function(RED) {
    const { KMSClient, EncryptCommand, DecryptCommand, GenerateDataKeyCommand } = require("@aws-sdk/client-kms");

    /**
     * AWS KMS Node constructor
     * 
     * @param {Object} config - Node configuration
     * @param {string} config.operation - Operation type: 'encrypt', 'decrypt', or 'generateDataKey'
     * @param {string} config.keyId - KMS key ID (optional for decrypt operation)
     * @param {string} config.region - AWS region
     * @param {string} config.keySpec - Key specification for generateDataKey (default: 'AES_256')
     */
    function AWSKMSNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        // Initialize AWS credentials
        const awsConfig = initializeAWSCredentials(node, config);
        if (!awsConfig) return;

        // Initialize KMS client
        const kmsClient = initializeKMSClient(node, awsConfig, config);
        if (!kmsClient) return;

        // Set initial node status
        updateNodeStatus(node, config);

        // Handle incoming messages
        node.on('input', async function(msg) {
            try {
                await processMessage(node, kmsClient, config, msg);
            } catch (error) {
                handleError(node, error);
            }
        });

        // Cleanup on node removal
        node.on('close', function() {
            if (kmsClient) {
                kmsClient.destroy();
            }
            node.status({});
        });
    }

    /**
     * Initialize AWS credentials from config node
     * 
     * @param {Object} node - Node-RED node instance
     * @param {Object} config - Node configuration
     * @returns {Object|null} AWS configuration object or null if initialization failed
     */
    function initializeAWSCredentials(node, config) {
        const awsConfig = RED.nodes.getNode(config.aws);
        if (!awsConfig) {
            node.error("AWS credentials not configured");
            node.status({fill:"red",shape:"ring",text:"No credentials"});
            return null;
        }
        return awsConfig;
    }

    /**
     * Initialize KMS client with proper configuration
     * 
     * @param {Object} node - Node-RED node instance
     * @param {Object} awsConfig - AWS configuration
     * @param {Object} config - Node configuration
     * @returns {KMSClient|null} KMS client instance or null if initialization failed
     */
    function initializeKMSClient(node, awsConfig, config) {
        try {
            const clientConfig = {
                region: config.region || 'us-east-1'
            };

            if (!awsConfig.useIAM) {
                if (!awsConfig.accessKeyId || !awsConfig.secretAccessKey) {
                    throw new Error("Access Key and Secret Key are required when not using IAM");
                }
                clientConfig.credentials = {
                    accessKeyId: awsConfig.accessKeyId,
                    secretAccessKey: awsConfig.secretAccessKey
                };
            }

            return new KMSClient(clientConfig);
        } catch (error) {
            node.error("AWS KMS Client Error: " + error.message);
            node.status({fill:"red",shape:"ring",text:"Client initialization failed"});
            return null;
        }
    }

    /**
     * Update node status based on configuration
     * 
     * @param {Object} node - Node-RED node instance
     * @param {Object} config - Node configuration
     */
    function updateNodeStatus(node, config) {
        if (config.operation !== 'decrypt' && !config.keyId) {
            node.status({fill:"yellow",shape:"ring",text:"Key ID needed in msg.keyId"});
        } else {
            node.status({});
        }
    }

    /**
     * Process incoming message based on operation type
     * 
     * @param {Object} node - Node-RED node instance
     * @param {KMSClient} kmsClient - KMS client instance
     * @param {Object} config - Node configuration
     * @param {Object} msg - Message object
     */
    async function processMessage(node, kmsClient, config, msg) {
        const keyId = config.keyId || msg.keyId;
        node.status({fill:"blue",shape:"dot",text:"Processing..."});

        switch (config.operation) {
            case 'encrypt':
                await handleEncrypt(node, kmsClient, keyId, msg);
                break;
            case 'decrypt':
                await handleDecrypt(node, kmsClient, msg);
                break;
            case 'generateDataKey':
                await handleGenerateDataKey(node, kmsClient, keyId, config, msg);
                break;
            default:
                throw new Error(`Unknown operation: ${config.operation}`);
        }

        updateNodeStatus(node, config);
        node.send(msg);
    }

    /**
     * Handle encryption operation
     * 
     * @param {Object} node - Node-RED node instance
     * @param {KMSClient} kmsClient - KMS client instance
     * @param {string} keyId - KMS key ID
     * @param {Object} msg - Message object
     */
    async function handleEncrypt(node, kmsClient, keyId, msg) {
        if (!msg.payload) {
            throw new Error("No data to encrypt");
        }
        if (!keyId) {
            throw new Error("Key ID required for encryption. Set it in node config or provide in msg.keyId");
        }

        const plaintext = preparePlaintext(msg.payload);
        const command = new EncryptCommand({
            KeyId: keyId,
            Plaintext: plaintext
        });

        const result = await kmsClient.send(command);
        msg.payload = Buffer.from(result.CiphertextBlob).toString('base64');
    }

    /**
     * Handle decryption operation
     * 
     * @param {Object} node - Node-RED node instance
     * @param {KMSClient} kmsClient - KMS client instance
     * @param {Object} msg - Message object
     */
    async function handleDecrypt(node, kmsClient, msg) {
        if (!msg.payload) {
            throw new Error("No data to decrypt");
        }

        const ciphertext = extractCiphertext(msg.payload);
        const command = new DecryptCommand({
            CiphertextBlob: Buffer.from(ciphertext, 'base64')
        });

        const result = await kmsClient.send(command);
        msg.payload = Buffer.from(result.Plaintext).toString('base64');
    }

    /**
     * Handle data key generation
     * 
     * @param {Object} node - Node-RED node instance
     * @param {KMSClient} kmsClient - KMS client instance
     * @param {string} keyId - KMS key ID
     * @param {Object} config - Node configuration
     * @param {Object} msg - Message object
     */
    async function handleGenerateDataKey(node, kmsClient, keyId, config, msg) {
        if (!keyId) {
            throw new Error("Key ID required for generating data key. Set it in node config or provide in msg.keyId");
        }

        const command = new GenerateDataKeyCommand({
            KeyId: keyId,
            KeySpec: config.keySpec || 'AES_256'
        });

        const result = await kmsClient.send(command);
        msg.payload = {
            plaintext: Buffer.from(result.Plaintext).toString('base64'),
            ciphertext: Buffer.from(result.CiphertextBlob).toString('base64')
        };
    }

    /**
     * Prepare plaintext for encryption
     * 
     * @param {string|Buffer} payload - Input payload
     * @returns {Buffer} Prepared plaintext buffer
     */
    function preparePlaintext(payload) {
        if (typeof payload === 'string' && isBase64(payload)) {
            return Buffer.from(payload, 'base64');
        }
        return Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
    }

    /**
     * Extract ciphertext from payload
     * 
     * @param {string|Object} payload - Input payload
     * @returns {string} Extracted ciphertext
     */
    function extractCiphertext(payload) {
        if (typeof payload === 'object' && payload.ciphertext) {
            return payload.ciphertext;
        }
        if (typeof payload !== 'string') {
            throw new Error("Payload must be a base64 string or object with .ciphertext");
        }
        return payload;
    }

    /**
     * Check if a string is base64 encoded
     * 
     * @param {string} str - String to check
     * @returns {boolean} True if string is base64 encoded
     */
    function isBase64(str) {
        try {
            return btoa(atob(str)) === str;
        } catch (err) {
            return false;
        }
    }

    /**
     * Handle node errors
     * 
     * @param {Object} node - Node-RED node instance
     * @param {Error} error - Error object
     */
    function handleError(node, error) {
        node.error("AWS KMS Error: " + error.message);
        node.status({fill:"red",shape:"dot",text:error.message});
    }

    // Register node type
    RED.nodes.registerType("aws-kms", AWSKMSNode);
} 