import {
  readFileSync,
} from 'fs'
import {
  sign,
  verify,
} from 'jsonwebtoken'



export interface Payload {
  user: string
  permissions: string[]
}

export interface DecodedToken extends Payload {
  iat: number   // 생성시간
  exp: number   // 만료시간
  iss: string   // 토큰 발급자
  sub: string   // 토큰 제목
}

export interface JwtConfig {
  secret: string        // 비밀키
  options: {
    expiresIn: string   // 만료 기간
    issuer: string      // 발급자
    subject: string     // 제목
  }
}


export class Authorizer {
  private _config: JwtConfig

  constructor(path: string)
  constructor(config: JwtConfig)
  constructor(arg: string | JwtConfig) {
    if(typeof arg === 'string') {
      this._config = JSON.parse(readFileSync(arg).toString())
    } else {
      this._config = arg
    }
  }

  sign(payload: Payload): string {
    return sign(payload, this._config.secret, this._config.options)
  }

  verify(token: string): Payload {
    // create a promise that decodes the token
    const decoded: DecodedToken = verify(token, this._config.secret) as DecodedToken
    return {
      user: decoded.user,
      permissions: decoded.permissions,
    }
  }
}

// todo: ./bin에 구현 
export function token(user: string, ...permissions: string[]): void {
  const auth = new Authorizer('./jwtconfig.json')
  console.log(auth.sign({user, permissions}))
}
