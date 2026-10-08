import { startRegistration } from '@simplewebauthn/browser';
import { webauthnRegisterOptions, webauthnRegisterVerify } from '../api/mfa';

export async function registerPasskey(): Promise<void> {
  const optionsJSON = await webauthnRegisterOptions();
  const credential = await startRegistration({ optionsJSON: optionsJSON as never });
  await webauthnRegisterVerify(credential);
}
