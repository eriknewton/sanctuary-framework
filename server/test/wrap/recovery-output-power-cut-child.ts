import { writeRecoveryKeyFile, type CustomRecoveryOutputStage } from "../../src/wrap/recovery-key-disclosure.js";

const storagePath = process.argv[2];
const outputPath = process.argv[3];
const targetStage = process.argv[4] as CustomRecoveryOutputStage | undefined;
if (!storagePath || !outputPath || !targetStage) throw new Error("missing fixture argument");

await writeRecoveryKeyFile({
  storagePath,
  ...(outputPath === "DEFAULT" ? {} : { recoveryKeyFilePath: outputPath }),
  recoveryKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  __testFaultAfterCustomOutputStage: async (stage) => {
    if (stage !== targetStage) return;
    process.stdout.write(`READY:${stage}\n`);
    await new Promise<never>(() => undefined);
  },
});
