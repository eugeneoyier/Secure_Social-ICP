import { Record, StableBTreeMap, Vec, Nat, match, Result, ic, Ed25519, Buffer } from 'azle';
import { sha256 } from 'js-sha256';
import * as crypto from 'crypto';
import * as dotenv from 'dotenv';

dotenv.config();

/* SecureSocial */
const messageStorage = new StableBTreeMap<string, SecureMessage>(0, 44, 1024);
const userStorage = new StableBTreeMap<string, User>(0, 44, 1024);
const userPublicKeyStorage = new StableBTreeMap<string, PublicKey>(0, 44, 1024);
const userPrivateKeyStorage = new StableBTreeMap<string, PrivateKey>(0, 44, 1024);

/* Message */
type Message = Record<{
    id: string;
    author_id: string;
    receiver_id: string;
    timestamp: Nat;
    content: string;
    type: string;
}>;

/* SecureMessage */
type SecureMessage = Message & Record<{
    nonce: string;
}>;

/* User */
type User = Record<{
    id: string;
    username: string;
    email: string;
    password: string;
    publicKey: PublicKey;
}>;

/* PublicKey */
type PublicKey = Record<{
    x: string;
    y: string;
}>;

/* PrivateKey */
type PrivateKey = Record<{
    d: string;
}>;

/* EncryptedMessage */
type EncryptedMessage = Record<{
    content: string;
    nonce: string;
}>;

/* Message Payload */
type MessagePayload = Record<{
    content: string;
    receiver_id: string;
    type: string;
}>;

/* Login Payload */
type LoginPayload = Record<{
    email: string;
    password: string;
}>;

/* Create User Payload */
type CreateUserPayload = Record<{
    username: string;
    email: string;
    password: string;
}>;

/* Get Users Payload */
type GetUsersPayload = Record<{
    limit: Nat;
}>;

/* Get Messages Payload */
type GetMessagesPayload = Record<{
    receiver_id: string;
    limit: Nat;
}>;

/* Helpers */
const generateNonce = (): string => {
    return sha256(Date.now().toString());
};

const encryptMessage = (publicKey: PublicKey, message: string, nonce: string): EncryptedMessage => {
    const ephemeralKey = generateEphemeralKey();
    const sharedSecret = generateSharedSecret(ephemeralKey, publicKey);
    const encryptedMessage = encrypt(sharedSecret, message, nonce);
    return {
        content: encryptedMessage,
        nonce: nonce,
    };
};

const decryptMessage = (privateKey: PrivateKey, encryptedMessage: EncryptedMessage): string => {
    const sharedSecret = generateSharedSecret(privateKey, encryptedMessage.nonce);
    const decryptedMessage = decrypt(sharedSecret, encryptedMessage.content, encryptedMessage.nonce);
    return decryptedMessage;
};

const generateEphemeralKey = (): { publicKey: PublicKey; privateKey: PrivateKey } => {
    const ed25519 = new Ed25519();
    const keyPair = ed25519.generateKeyPair();
    return {
        publicKey: {
            x: Buffer.from(keyPair.publicKey).toString('base64'),
            y: Buffer.from(keyPair.publicKey).toString('base64'),
        },
        privateKey: {
            d: Buffer.from(keyPair.privateKey).toString('base64'),
        },
    };
};

const generateSharedSecret = (privateKey: PrivateKey | PublicKey, publicKey: PublicKey): string => {
    const ed25519 = new Ed25519();
    const sharedSecret = ed25519.sharedKey(
        Buffer.from(privateKey.d, 'base64'),
        Buffer.from(publicKey.x, 'base64'),
        Buffer.from(publicKey.y, 'base64')
    );
    return Buffer.from(sharedSecret).toString('base64');
};

const encrypt = (sharedSecret: string, message: string, nonce: string): string => {
    const hmac = sha256Crypto.create();
    hmac.update(sharedSecret + nonce);
    const key = hmac.digest('base64');
    const iv = new Uint8Array(12);
    window.crypto.getRandomValues(iv);
    // Note: Replace AesCtr with the appropriate AES encryption implementation
    const aes = new AesCtr(key);
    const encryptedMessage = aes.encrypt(message, iv);
    return Buffer.from(encryptedMessage).toString('base64');
};

const decrypt = (sharedSecret: string, encryptedMessage: string, nonce: string): string => {
    const hmac = sha256Crypto.create();
    hmac.update(sharedSecret + nonce);
    const key = hmac.digest('base64');
    const iv = new Uint8Array(12);
    window.crypto.getRandomValues(iv);
    // Note: Replace AesCtr with the appropriate AES decryption implementation
    const aes = new AesCtr(key);
    const decryptedMessage = aes.decrypt(Buffer.from(encryptedMessage, 'base64'), iv);
    return decryptedMessage.toString('utf-8');
};

/* User Functions */
export function login(payload: LoginPayload): Result<User, string> {
    const passwordHash = sha256(payload.password);
    const users = userStorage.values() ?? [];
    const user = users.find((u) => u.email === payload.email && compareHashes(u.password, passwordHash));

    return user ? Result.Ok<User, string>(user) : Result.Err<User, string>(`invalid email or password`);
}

// Helper function for secure hash comparison
function compareHashes(hashA: string, hashB: string): boolean {
    if (a.length !== b.length) {
        return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
}

function performEncryption(data: string, secretKey: string): string {
    const ivLength = 16;
    const iv = crypto.randomBytes(ivLength);
    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    let encryptedData = cipher.update(data, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return iv.toString('hex') + ':' + authTag + ':' + encryptedData;
}

function performDecryption(encryptedData: string, secretKey: string): string {
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts.shift() as string, 'hex');
    const authTag = Buffer.from(parts.shift() as string, 'hex');
    const data = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, iv);
    decipher.setAuthTag(authTag);
    let decryptedData = decipher.update(data, undefined, 'utf8');
    decryptedData += decipher.final('utf8');
    return decryptedData;
}

function encryptPrivateKey(privateKey: PrivateKey, secretKey: string): string {
    const encryptedPrivateKey = performEncryption(privateKey, secretKey);
    return encryptedPrivateKey;
}

export function createUser(payload: CreateUserPayload): Result<User, string> {
    // Input validation
    if (!payload.username || !payload.email || !payload.password) {
        return Result.Err<User, string>('Username, email, and password are required.');
    }
    if (payload.username.length < 3 || payload.username.length > 30) {
        return Result.Err<User, string>('Username must be between  3 and  30 characters long.');
    }
    if (!isEmailValid(payload.email)) {
        return Result.Err<User, string>('Invalid email address.');
    }
    if (payload.password.length < 8 || payload.password.length > 30) {
        return Result.Err<User, string>('Password must be between  8 and  30 characters long.');
    }

    const id = sha256(payload.username + payload.email);
    const passwordHash = sha256(payload.password);

    const newUser: User = {
        id: id,
        username: payload.username,
        email: payload.email,
        password: passwordHash,
        publicKey: generateEphemeralKey().publicKey,
    };

    const newUserPrivateKey: PrivateKey = generateEphemeralKey().privateKey;
    userStorage.insert(newUser.id, newUser);
    userPublicKeyStorage.insert(newUser.id, newUser.publicKey);
    const encryptedPrivateKey = encryptPrivateKey(newUserPrivateKey, process.env.SECRET_KEY);
    userPrivateKeyStorage.insert(newUser.id, encryptedPrivateKey);

    return Result.Ok<User, string>(newUser);
}

// Helper function to validate email addresses using a simple regex
function isEmailValid(email: string): boolean {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

export function getUser(id: string): Result<User, string> {
    return match(userStorage.get(id), {
        Some: (user) => Result.Ok<User, string>(user),
        None: () => Result.Err<User, string>(`user with id=${id} not found`),
    });
}

/* Message Functions */
export function sendMessage(payload: MessagePayload): Result<SecureMessage, string> {
    const senderId = ic.caller();
    const receiverId = payload.receiver_id;

    const sender = match(userStorage.get(senderId), {
        Some: (user) => user,
        None: () => Result.Err<User, string>(`sender with id=${senderId} not found`),
    });

    const receiver = match(userStorage.get(receiverId), {
        Some: (user) => user,
        None: () => Result.Err<User, string>(`receiver with id=${receiverId} not found`),
    });

    const newMessage: SecureMessage = {
        id: sha256(sender.id + receiver.id + Date.now().toString()),
        author_id: sender.id,
        receiver_id: receiver.id,
        timestamp: ic.time(),
        content: payload.content,
        nonce: generateNonce(),
        type: payload.type,
    };

    messageStorage.insert(newMessage.id, newMessage);

    return Result.Ok<SecureMessage, string>(newMessage);
}

export function getMessages(payload: GetMessagesPayload): Result<Vec<SecureMessage>, string> {
    return match(messageStorage.values(), {
        Some: (messages) => {
            // Filter received messages
            const receivedMessages = messages.filter((m) => m.receiver_id === payload.receiver_id);
            // Sort messages by timestamp
            const sortedMessages = receivedMessages.sort((a, b) => b.timestamp - a.timestamp);
            // Limit messages
            const limitedMessages = sortedMessages.slice(0, payload.limit);
            return Result.Ok<Vec<SecureMessage>, string>(limitedMessages);
        },
        None: () => Result.Err<Vec<SecureMessage>, string>(`no messages found`),
    });
}

/* Login Functions */
export function login(payload: LoginPayload): Result<User, string> {
    const passwordHash = sha256(payload.password);
    const users = userStorage.values() ?? [];
    const user = users.find((u) => u.email === payload.email && compareHashes(u.password, passwordHash));

    return user ? Result.Ok<User, string>(user) : Result.Err<User, string>(`invalid email or password`);
}

// Helper function for secure hash comparison
function compareHashes(hashA: string, hashB: string): boolean {
    if (a.length !== b.length) {
        return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
}

/* Unit Tests */
export function test(n: Nat): Vec<Result<string, string>> {
    const results = Vec.empty<Result<string, string>>();
    for (let i = 0; i < n; i++) {
        // Generate ephemeral key pair for testing
        const ephemeralKeyPair = generateEphemeralKey();
        const ephemeralPublicKey = ephemeralKeyPair.publicKey;
        const ephemeralPrivateKey = ephemeralKeyPair.privateKey;

        // Encrypt a message using the ephemeral public key and decrypt it using the ephemeral private key
        const encryptedMessage = encryptMessage(ephemeralPublicKey, 'Hello, world!', generateNonce());
        const decryptedMessage = decryptMessage(ephemeralPrivateKey, encryptedMessage);

        // Check if the decrypted message matches the original message
        if (decryptedMessage === 'Hello, world!') {
            results.push(Result.Ok<string, string>('Message encryption and decryption successful'));
        } else {
            results.push(Result.Err<string, string>('Message encryption or decryption failed'));
        }
    }
    return results;
}
