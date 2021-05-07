import * as vscode from "vscode";
import {
  Authorizer,
  OidcGrantTypes,
  OidcProviderConfiguration,
} from "./auth-provider";

export async function activate(context: vscode.ExtensionContext) {
  Authorizer.createInstance(
    "mycustomauth",
    new OidcProviderConfiguration(
      vscode.Uri.parse("http://localhost:8080/auth/realms/myapp/protocol"),
      vscode.Uri.parse("http://localhost:8080"), // Placeholder
      "vscode-ext",
      undefined,
      "email profile openid",
      OidcGrantTypes.password
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("extension.helloWorld", async () => {
      const session = await vscode.authentication.getSession(
        "mycustomauth",
        ["profile", "email"],
        { createIfNone: true }
      );
      console.log(session);
    })
  );
}
