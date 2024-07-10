/**
 * Created by AKuzmanoski on 31/01/2017.
 */
import {Injectable, OnDestroy, OnInit} from '@angular/core';
import {STOMPService} from './stopm.service';
import {ConfigService} from '../config/config.service';
import {Message} from 'stompjs';
import {BehaviorSubject, Observable} from 'rxjs';
import {StompConfig} from './stomp.config';
import {Notice} from '../../domain/model/sharing/notice';
import {AccessTokenContext} from '../authentication/token/access-token-context';
import {TokenValidator} from '../authentication/token/token-validator';
import {RefreshAccessTokenService} from '../authentication/token/refresh-access-token.service';
import {AuthenticationService} from '../authentication/authentication.service';

@Injectable()
export class SocketService implements OnInit, OnDestroy {

    private config: StompConfig;
    private configured = false;
    private messages: Observable<Message>;
    private noticeMessage: BehaviorSubject<Notice> = new BehaviorSubject<Notice>(null);
    private noticeCountMessage: BehaviorSubject<number> = new BehaviorSubject<number>(0);

    public on_connect = () => {

        // Store local reference to Observable
        // for use with template ( | async )
        this.messages = this.stomp.messages;

        // Subscribe a function to be run on_next message
        this.messages.subscribe(this.on_next);
    };
    public on_next = (message: any) => {
        // Log it to the console
        if (message.headers.destination === '/user/topic/notices') {
            this.noticeMessage.next(JSON.parse(message.body));
        } else if (message.headers.destination === '/user/topic/notices/count') {
            this.noticeCountMessage.next(JSON.parse(message.body));
        }
    };

    constructor(private stomp: STOMPService,
                private accessTokenContext: AccessTokenContext,
                private tokenValidator: TokenValidator,
                private configService: ConfigService,
                private refreshTokenService: RefreshAccessTokenService,
                private authenticationService: AuthenticationService) {
        configService.getConfig('/assets/socket/config.json').subscribe(
            (config: StompConfig) => {
                // ... then pass it to (and connect) STOMP:
                this.config = config;

                this.tryConnect(this.authenticationService.isAuthenticated());
            });

        accessTokenContext.getObservable().subscribe((token: string) => {
            this.tryConnect(this.authenticationService.isAuthenticated());
        });
    }

    private tryConnect(isAuthenticated: boolean) {
        if (isAuthenticated) {
            this.getToken().subscribe((token: string) => {
                this.config.user = this.formToken(token);
                this.stomp.configure(this.config);
                this.configured = true;
                this.stomp.try_connect().then(this.on_connect);
            });
        } else {
            this.stomp.disconnect(() => {
            });
        }
    }

    private getToken(): Observable<string> {
        return Observable.create(observer => {
            let token: string = this.accessTokenContext.get();
            if (!this.tokenValidator.isValid(token)) {
                this.refreshTokenService.getNewAccessToken()
                    .subscribe((newToken: string) => {
                        token = newToken;
                        observer.next(token)
                    });
            }
            observer.next(token);
        });
    }

    public newNoticeMessage(): Observable<any> {
        return this.noticeMessage.asObservable();
    }

    public newNoticeCountMessage(): Observable<any> {
        return this.noticeCountMessage.asObservable();
    }

    ngOnInit(): void {

    }

    ngOnDestroy(): void {
        this.stomp.disconnect(() => {
        });
    }

    public sendMessage(message: string) {
        this.stomp.publish(message);
    }

    private formToken(token: string) {
        let fullToken = '';
        if (token) {
            fullToken = 'Bearer ' + token;
        }
        return fullToken;
    }
}
