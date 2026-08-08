export class Bip324Error extends Error {
  constructor(
    message: string,
    readonly code: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class AuthenticationError extends Bip324Error {
  constructor(message = "BIP-324 packet authentication failed") {
    super(message, "ERR_BIP324_AUTHENTICATION");
  }
}

export class ProtocolClosedError extends Bip324Error {
  constructor(options?: ErrorOptions) {
    super("BIP-324 protocol session is closed", "ERR_BIP324_CLOSED", options);
  }
}

export class V1DetectedError extends Bip324Error {
  readonly buffered: Uint8Array;

  constructor(buffered: Uint8Array) {
    super("peer selected Bitcoin P2P v1 transport", "ERR_BIP324_V1_DETECTED");
    this.buffered = buffered.slice();
  }
}
