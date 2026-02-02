import type { PatternDefinition } from '../types.js'

export const privateKeyPatterns: PatternDefinition[] = [
  // RSA Private Keys
  {
    id: 'rsa-private-key',
    name: 'RSA Private Key',
    description: 'RSA private key in PEM format',
    severity: 'critical',
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    keywords: ['rsa', 'private', 'key', 'pem', 'certificate'],
    validators: [],
    examples: {
      positive: [
        '-----BEGIN RSA PRIVATE KEY-----\nMIIE...base64...\n-----END RSA PRIVATE KEY-----',
      ],
      negative: [],
    },
  },
  {
    id: 'encrypted-rsa-private-key',
    name: 'Encrypted RSA Private Key',
    description: 'Encrypted RSA private key in PEM format',
    severity: 'high',
    pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]*?-----END ENCRYPTED PRIVATE KEY-----/g,
    keywords: ['rsa', 'private', 'key', 'encrypted', 'pem'],
    validators: [],
    examples: {
      positive: [],
      negative: [],
    },
  },

  // Generic Private Keys
  {
    id: 'private-key',
    name: 'Private Key',
    description: 'Generic private key in PEM format',
    severity: 'critical',
    pattern: /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g,
    keywords: ['private', 'key', 'pem'],
    validators: [],
    examples: {
      positive: ['-----BEGIN PRIVATE KEY-----\nMIIE...base64...\n-----END PRIVATE KEY-----'],
      negative: [],
    },
  },

  // EC Private Keys
  {
    id: 'ec-private-key',
    name: 'EC Private Key',
    description: 'Elliptic Curve private key in PEM format',
    severity: 'critical',
    pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g,
    keywords: ['ec', 'elliptic', 'curve', 'private', 'key'],
    validators: [],
    examples: {
      positive: [],
      negative: [],
    },
  },

  // DSA Private Keys
  {
    id: 'dsa-private-key',
    name: 'DSA Private Key',
    description: 'DSA private key in PEM format',
    severity: 'critical',
    pattern: /-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----/g,
    keywords: ['dsa', 'private', 'key'],
    validators: [],
    examples: {
      positive: [],
      negative: [],
    },
  },

  // OpenSSH Private Keys
  {
    id: 'openssh-private-key',
    name: 'OpenSSH Private Key',
    description: 'OpenSSH format private key',
    severity: 'critical',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
    keywords: ['openssh', 'ssh', 'private', 'key'],
    validators: [],
    examples: {
      positive: [],
      negative: [],
    },
  },

  // PuTTY Private Keys
  {
    id: 'putty-private-key',
    name: 'PuTTY Private Key',
    description: 'PuTTY PPK format private key',
    severity: 'critical',
    pattern: /PuTTY-User-Key-File-\d+:[\s\S]*?Private-Lines:/g,
    keywords: ['putty', 'ppk', 'private', 'key'],
    validators: [],
    examples: {
      positive: [],
      negative: [],
    },
  },

  // PGP Private Keys
  {
    id: 'pgp-private-key',
    name: 'PGP Private Key',
    description: 'PGP/GPG private key block',
    severity: 'critical',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g,
    keywords: ['pgp', 'gpg', 'private', 'key'],
    validators: [],
    examples: {
      positive: [],
      negative: [],
    },
  },

  // Certificates
  {
    id: 'x509-certificate',
    name: 'X.509 Certificate',
    description: 'X.509 certificate in PEM format (may contain sensitive info)',
    severity: 'medium',
    pattern: /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    keywords: ['certificate', 'x509', 'pem', 'ssl', 'tls'],
    validators: [],
    examples: {
      positive: [],
      negative: [],
    },
  },

  // PKCS#12
  {
    id: 'pkcs12-reference',
    name: 'PKCS#12 Reference',
    description: 'Reference to PKCS#12/PFX file with potential password',
    severity: 'high',
    pattern: /(?:\.pfx|\.p12)\s*[,;]?\s*(?:password|pass|pwd)\s*[:=]\s*["']?[^\s"']+["']?/gi,
    keywords: ['pkcs12', 'pfx', 'p12', 'certificate', 'password'],
    validators: [],
    examples: {
      positive: ['certificate.pfx, password=mysecret'],
      negative: [],
    },
  },

  // SSH Keys (public key sometimes paired with private)
  {
    id: 'ssh-private-key-file',
    name: 'SSH Private Key Reference',
    description: 'Reference to SSH private key file',
    severity: 'medium',
    pattern:
      /(?:identity|identity_file|identityfile|ssh.?key|private.?key)\s*[:=]\s*["']?[^\s"']+["']?/gi,
    keywords: ['ssh', 'identity', 'key', 'private'],
    validators: [],
    examples: {
      positive: ['IdentityFile ~/.ssh/id_rsa'],
      negative: [],
    },
  },
]
