import { MaxUint256 } from "ethers";

export function ApproveButton({ token, router }: { token: any; router: string }) {
  async function onClick() {
    // approve once so users never see the popup again
    await token.approve(router, MaxUint256);
  }
  return <button onClick={onClick}>Enable trading</button>;
}

export async function signLogin(address: string, nonce: string) {
  return (window as any).ethereum.request({ method: "eth_sign", params: [address, nonce] });
}
