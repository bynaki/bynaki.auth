import test from 'ava'
import {
  Authorizer, Payload,
} from '../src'



test('must authorize', t => {
  const auth = new Authorizer({
    secret: 'sshh',
    options: {
      expiresIn: '1d',
      issuer: 'bynaki',
      subject: 'auth',
    }
  })
  const payload: Payload = {
    user: 'naki',
    permissions: ['level01'],
  }
  const encoded = auth.sign(payload)
  const decoded = auth.verify(encoded)
  t.deepEqual(payload, decoded)
})

test('bad tokken', t => {
  const auth = new Authorizer({
    secret: 'sshh',
    options: {
      expiresIn: '1d',
      issuer: 'bynaki',
      subject: 'auth',
    }
  })
  const err = t.throws(() => auth.verify('bad token'))
  t.is(err.message, 'jwt malformed')
})

test('expired', t => {
  const auth = new Authorizer({
    secret: 'sshh',
    options: {
      expiresIn: '1ms',
      issuer: 'bynaki',
      subject: 'auth',
    }
  })
  const payload: Payload = {
    user: 'naki',
    permissions: ['level01'],
  }
  const encoded = auth.sign(payload)
  const err = t.throws(() => auth.verify(encoded))
  t.is(err.message, 'jwt expired')
})

test('from file', t => {
  const auth = new Authorizer('./jwtconfig.base.json')
  const payload: Payload = {
    user: 'naki',
    permissions: ['level01'],
  }
  const encoded = auth.sign(payload)
  const decoded = auth.verify(encoded)
  t.deepEqual(payload, decoded)
})
