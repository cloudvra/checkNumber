# Auth Token Handle gracefully

## 1. Store token centrally
Use a variable in the test context or `Cypress.env()` to store the current token.

## 2. Create a token-aware `cy.apiRequest()` wrapper
```typescript
// cypress/support/commands.js

let accessToken = null

Cypress.Commands.add('getAccessToken', () => {
  // Reuse if already available
  if (accessToken) return cy.wrap(accessToken)

  // Otherwise, fetch token
  return cy.request({
    method: 'POST',
    url: '/auth/token',
    body: {
      client_id: 'your_client_id',
      client_secret: 'your_secret',
      grant_type: 'client_credentials'
    },
  }).then((res) => {
    accessToken = res.body.access_token
    return accessToken
  })
})

Cypress.Commands.add('apiRequest', (options) => {
  // Handle expired tokens using retry logic if needed
  return cy.getAccessToken().then((token) => {
    const authOptions = {
      ...options,
      headers: {
        ...(options.headers || {}),
        Authorization: `Bearer ${token}`
      }
    }

    return cy.request(authOptions).then((response) => {
      if (response.status === 401) {
        // If unauthorized, try refreshing the token
        accessToken = null
        return cy.getAccessToken().then((newToken) => {
          return cy.request({
            ...options,
            headers: {
              ...(options.headers || {}),
              Authorization: `Bearer ${newToken}`
            }
          })
        })
      }

      return response
    })
  })
})
```
## 3. Use in Tests Like This
```typescript
// Your test file
it('fetches protected data using auto token handling', () => {
  cy.apiRequest({
    method: 'GET',
    url: '/api/secure-data'
  }).then((res) => {
    expect(res.status).to.eq(200)
    expect(res.body).to.have.property('data')
  })
})
```
