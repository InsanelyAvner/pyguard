import { dirname } from "path";
import { fileURLToPath } from "url";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({
  baseDirectory: __dirname,
});

const eslintConfig = [
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    rules: {
      // completely disable `any` checks:
      "react-hooks/exhaustive-deps": "off",
      "@typescript-eslint/no-explicit-any": "off",
      // disable unused-vars or adjust its pattern to ignore e.g. `ids`
      "@typescript-eslint/no-unused-vars": [
        "off"
        // or to keep it on but ignore `ids`:
        // ["error", { varsIgnorePattern: "^ids$", argsIgnorePattern: "^_" }]
      ],
    },
  },
];

export default eslintConfig;
