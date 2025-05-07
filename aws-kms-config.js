/**
 * AWS KMS Configuration Node
 * 
 * This module provides configuration for AWS KMS operations in Node-RED.
 * It supports both IAM roles and access key authentication, including temporary credentials.
 * 
 * @module node-red-contrib-aws-kms-config
 */

module.exports = function(RED) {
    /**
     * AWS KMS Configuration Node constructor
     * 
     * @param {Object} config - Node configuration
     * @param {string} config.name - Node name
     * @param {boolean} config.useIAM - Whether to use IAM role
     */
    function AWSKMSConfigNode(config) {
        RED.nodes.createNode(this, config);
        
        // Basic configuration
        this.name = config.name;
        this.useIAM = config.useIAM;

        // Handle credentials
        if (this.credentials) {
            this.accessKeyId = this.credentials.accessKey;
            this.secretAccessKey = this.credentials.secretKey;
            this.sessionToken = this.credentials.sessionToken;
        }

        // Validate configuration
        this.validateConfig();
    }

    /**
     * Validate node configuration
     * @throws {Error} If configuration is invalid
     */
    AWSKMSConfigNode.prototype.validateConfig = function() {
        if (!this.useIAM) {
            if (!this.accessKeyId || !this.secretAccessKey) {
                throw new Error("Access Key and Secret Key are required when not using IAM");
            }
        }
    };

    /**
     * Get AWS credentials
     * @returns {Object} AWS credentials object
     */
    AWSKMSConfigNode.prototype.getCredentials = function() {
        if (this.useIAM) {
            return {
                useIAM: true
            };
        }

        const credentials = {
            accessKeyId: this.accessKeyId,
            secretAccessKey: this.secretAccessKey
        };

        if (this.sessionToken) {
            credentials.sessionToken = this.sessionToken;
        }

        return credentials;
    };

    // Register node type with credentials
    RED.nodes.registerType("aws-kms-config", AWSKMSConfigNode, {
        credentials: {
            accessKey: { type: "text" },
            secretKey: { type: "password" },
            sessionToken: { type: "password" }
        }
    });
} 