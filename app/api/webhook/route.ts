import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import crypto from "crypto";

export const config = {
  api: {
    bodyParser: false, 
  },
};

//Changes test
//Chanegs 2 
//chanhcjebvkjefhbvced

const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET!;

async function verifySignature(signature: string | null, body: Buffer): Promise<boolean> {
  if (!signature) return false;
  const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET);
  hmac.update(body);
  const digest = `sha256=${hmac.digest("hex")}`;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
}

export async function POST(req: NextRequest) {
  const rawBody = await req.arrayBuffer();
  const bodyBuffer = Buffer.from(rawBody);
  const signature = req.headers.get("x-hub-signature-256");

  if (!(await verifySignature(signature, bodyBuffer))) {
    console.error("Invalid signature ➞ rejecting webhook");
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  const event = req.headers.get("x-github-event");
  const payload = JSON.parse(bodyBuffer.toString());

  if (event === "pull_request") {
    const { action, number } = payload.pull_request;
    const repo = payload.repository.full_name;
    console.log(`PR #${number} ${action} in ${repo}`);
  }

  return NextResponse.json({ ok: true });
}
