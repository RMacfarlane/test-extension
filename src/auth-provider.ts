import * as vscode from 'vscode';
import axios, { AxiosResponse } from 'axios';

export enum OidcGrantTypes {
    password = "password",
    code = "code",
    token = "token"
}

export class OidcProviderConfiguration {
    constructor(
        public readonly idpBaseUrl: vscode.Uri,
        public readonly redirectUrl: vscode.Uri,
        public readonly clientId: string,
        public readonly clientSecret: string | undefined,
        public readonly scopes: string,
        public readonly grantType: OidcGrantTypes = OidcGrantTypes.password,
    ){}
}

export class OidcCredentials {
    
    public readonly readableIdToken : any | undefined;
    public readonly readableAccessToken : any;
    public get authTokensExpired() : boolean {
        return (new Date().getTime() - this.authTokensExpiration) > 0;
    }

    public get refreshTokenExpired() : boolean {
        return (new Date().getTime() - this.refreshTokenExpiration) > 0;
    }
    
    constructor(
        public readonly idToken: string | undefined,
        public readonly accessToken: string,
        public readonly refreshToken: string,
        public readonly authTokensExpiration: number,
        public readonly refreshTokenExpiration: number,

    ){
        if(idToken)
            this.readableIdToken = JSON.parse(Buffer.from(idToken.split(".")[1],'base64').toString());
        this.readableAccessToken = JSON.parse(Buffer.from(accessToken.split(".")[1],'base64').toString());

        this.authTokensExpiration = (new Date()).getTime() + this.authTokensExpiration*1000;
        this.refreshTokenExpiration = (new Date()).getTime() + this.refreshTokenExpiration*1000;
    }

    public serialize(): any {
        return {
            id_token: this.idToken,
            access_token: this.accessToken,
            refresh_token: this.refreshToken,
            auth_tokens_expiration: this.authTokensExpiration,
            refresh_token_expiration: this.refreshTokenExpiration,
        }
    }

    public static deserialize(descriptor: any): OidcCredentials {
        return new OidcCredentials(
            descriptor.id_token,
            descriptor.access_token,
            descriptor.refresh_token,
            descriptor.auth_tokens_expiration,
            descriptor.refresh_token_expiration
        );
    }
}

interface AuthUserDescriptor extends vscode.AuthenticationSession {
    expired: boolean;
}

/**
 * @class
 * @implements {vscode.AuthenticationProvider}
 * @description Authorizer allows user authentication OIDC protocol based on vscode platform. Singleton instance can be used across vscode extensions. No multiple user sessions are supported
 */
export class Authorizer implements vscode.AuthenticationProvider {

    private currentUser : AuthUserDescriptor | undefined;

    private _onDidChangeSessions: vscode.EventEmitter<vscode.AuthenticationProviderAuthenticationSessionsChangeEvent> = new vscode.EventEmitter<vscode.AuthenticationProviderAuthenticationSessionsChangeEvent>();

    private constructor(public readonly oidcProviderConf: OidcProviderConfiguration) {
        this.onDidChangeSessions = this._onDidChangeSessions.event;
    }

    public onDidChangeSessions: vscode.Event<vscode.AuthenticationProviderAuthenticationSessionsChangeEvent>;

    public async getSessions(scopes?: string[]): Promise<readonly vscode.AuthenticationSession[]> {
        let result : Array<vscode.AuthenticationSession> = [];
        if(this.currentUser && !this.currentUser.expired) 
            result.push(this.currentUser);
        return result;
    }

    public async createSession(scopes: string[]): Promise<vscode.AuthenticationSession> {
        if(this.currentUser  && !this.currentUser?.expired)
            throw new Error("User session is already active");

        const session : vscode.AuthenticationSession = await this.login();
        
        this._onDidChangeSessions.fire({ added: [ session ], removed: [], changed: [] });
        return session;
    }

    public async removeSession(sessionId: string): Promise<void> {
        const session : vscode.AuthenticationSession = await this.logout();
        this._onDidChangeSessions.fire({ removed: [ session ], added: [], changed: [] });
    }

    /**
     * @static @method createInstance
     * 
     * @description Register a singleton Authorizer instance for specified namespace if it doesn't exist
     * @param namespaceApp Application namespace for the authorizer
     * @param oidcProviderConf OIDC provider parameters
     */
    public static createInstance(namespaceApp: string, oidcProviderConf: OidcProviderConfiguration) : Authorizer {

        try {
            const authorizer = new Authorizer(oidcProviderConf);
            vscode.authentication.registerAuthenticationProvider(namespaceApp,namespaceApp, authorizer);
            return authorizer;
        } catch (error) {
            const message = "Authentication provider already exist for " + namespaceApp;
            throw new Error(message);
        }
    }

    private async login(): Promise<AuthUserDescriptor> {
        switch(this.oidcProviderConf.grantType){
            case OidcGrantTypes.password:
                const username: string | undefined = await vscode.window.showInputBox({placeHolder: "Insert username"});
                const password: string | undefined = await vscode.window.showInputBox({placeHolder: "Insert password", password: true});
                const url : vscode.Uri = vscode.Uri.joinPath(this.oidcProviderConf.idpBaseUrl , "/openid-connect/token");
                const body : string =   "client_id="        + this.oidcProviderConf.clientId        +
                                        "&client_secret="   + this.oidcProviderConf.clientSecret    +
                                        "&scopes="          + this.oidcProviderConf.scopes          +
                                        "&grant_type="      + this.oidcProviderConf.grantType       +
                                        "&username="        + username                              +
                                        "&password="        + password 
                // const response : AxiosResponse = await axios.post(url.toString(), body, { headers: { "Content-Type": "application/x-www-form-urlencoded" }});
                // const idToken : string | undefined = response.data.id_token;
                // const accessToken : string = response.data.access_token;
                // const refreshToken : string = response.data.refresh_token;
                // const authTokensExpiration: number = response.data.expires_in;
                // const refreshTokenExpiration : number = response.data.refresh_expires_in;
                const currentUserDescriptor = {
                    id: 'test',
                    accessToken: 'test',
                    scopes: this.oidcProviderConf.scopes.split(' '),
                    account: {
                        id: 'test',
                        label: 'test'
                    },
                    expired: false

                }
                this.currentUser = currentUserDescriptor;
                break
            case OidcGrantTypes.code:
            case OidcGrantTypes.token:
                break;
            default:
                throw new Error("OIDC grant type not supported");
        }
        if(!this.currentUser)
            throw new Error("Login failed");
        return this.currentUser;
    }

    private async refresh() {
        throw new Error("Method not implemented");
    }

    private async logout() : Promise<AuthUserDescriptor> {
        if(!this.currentUser)
            throw new Error("No current user session available");

        const url : vscode.Uri = vscode.Uri.joinPath(this.oidcProviderConf.idpBaseUrl , "/openid-connect/token");
        const body : string =   "token=" + this.currentUser.accessToken +
                                "&token_type_hint=access_token" 
        const response : AxiosResponse = await axios.post(url.toString(), body, { headers: { "Content-Type": "application/x-www-form-urlencoded" }});
        console.log(response);
        const currentUserDescriptor : AuthUserDescriptor = this.currentUser;
        return currentUserDescriptor;
    }
}