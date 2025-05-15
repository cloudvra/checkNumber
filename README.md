# Cypress API Automation Framework - Complete Guide

## 1. Directory Structure
```bash
cypress/
├── e2e/
│   ├── bdd/                   # Cucumber feature files
│   │   └── *.feature
│   └── api/                   # Standard API tests
│       └── *.spec.js
├── fixtures/
│   └── test-data/             # Static test data
├── support/
│   ├── api/
│   │   ├── auth/              # OAuth 2.0 implementation
│   │   │   └── oauth.ts
│   │   ├── schemas/           # Zod schemas
│   │   │   └── *.ts
│   │   ├── templates/         # Request body templates
│   │   │   └── *.ts
│   │   └── client.ts          # API client
│   ├── commands.ts            # Custom commands
│   ├── e2e.ts                 # Standard support file
│   └── bdd.ts                 # Cucumber support file
├── plugins/
│   └── index.ts               # Plugins configuration
└── reports/                   # Test reports
```
## 2. OAuth 2.0 Token Management ```cypress/support/api/auth/oauth.ts:```
```typescript
import { z } from 'zod';

const TokenSchema = z.object({
  access_token: z.string(),
  token_type: z.string(),
  expires_in: z.number(),
  refresh_token: z.string().optional(),
});

let currentToken: z.infer<typeof TokenSchema> | null = null;
let tokenExpiryTime: number | null = null;

export const getAuthToken = async (): Promise<string> => {
  if (!currentToken || isTokenExpired()) {
    await refreshToken();
  }
  return currentToken!.access_token;
};

const isTokenExpired = (): boolean => {
  if (!tokenExpiryTime) return true;
  return Date.now() >= tokenExpiryTime - 30000; // 30-second buffer
};

const refreshToken = async (): Promise<void> => {
  const response = await cy.request({
    method: 'POST',
    url: Cypress.env('authUrl'),
    form: true,
    body: {
      grant_type: 'client_credentials',
      client_id: Cypress.env('clientId'),
      client_secret: Cypress.env('clientSecret'),
      scope: Cypress.env('scope'),
    },
  });

  currentToken = TokenSchema.parse(response.body);
  tokenExpiryTime = Date.now() + currentToken.expires_in * 1000;
};
```
## 3. API Client with Zod Validation
```cypress/support/api/client.ts:```
```typescript
import { z, ZodType } from 'zod';
import { getAuthToken } from './auth/oauth';

export class ApiClient {
  static async request<T extends ZodType>(options: {
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    url: string;
    schema: T;
    body?: unknown;
    headers?: Record<string, string>;
  }): Promise<z.infer<T>> {
    const token = await getAuthToken();
    
    const defaultHeaders = {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    };

    return cy.request({
      method: options.method,
      url: options.url,
      headers: { ...defaultHeaders, ...options.headers },
      body: options.body,
    }).then((response) => {
      const parsed = options.schema.safeParse(response.body);
      if (!parsed.success) {
        throw new Error(`Response validation failed: ${parsed.error}`);
      }
      return parsed.data;
    });
  }
}
```
## 4. Request Body Templates with Faker
```cypress/support/api/templates/user.ts:```
```typescript
import { faker } from '@faker-js/faker';
import { z } from 'zod';

export const UserCreateSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  password: z.string().min(8),
  address: z.object({
    street: z.string(),
    city: z.string(),
    zipCode: z.string(),
  }).optional(),
});

export type UserCreatePayload = z.infer<typeof UserCreateSchema>;

export const generateUserCreatePayload = (
  overrides?: Partial<UserCreatePayload>
): UserCreatePayload => ({
  name: faker.person.fullName(),
  email: faker.internet.email(),
  password: faker.internet.password(),
  address: {
    street: faker.location.streetAddress(),
    city: faker.location.city(),
    zipCode: faker.location.zipCode(),
  },
  ...overrides,
});
```
## 5. Cucumber Integration
```Install required packages: ```
```bash
npm install @badeball/cypress-cucumber-preprocessor @bahmutov/cypress-esbuild-preprocessor --save-dev
```
```cypress.config.ts:```
```typescript
import { defineConfig } from 'cypress';
import createBundler from '@bahmutov/cypress-esbuild-preprocessor';
import { addCucumberPreprocessorPlugin } from '@badeball/cypress-cucumber-preprocessor';

export default defineConfig({
  e2e: {
    specPattern: ['**/*.feature', '**/*.spec.ts'],
    async setupNodeEvents(on, config) {
      await addCucumberPreprocessorPlugin(on, config);
      
      on(
        'file:preprocessor',
        createBundler({
          plugins: [createEsbuildPlugin(config)],
        })
      );
      
      return config;
    },
  },
});
```

### Example feature file:
```gherkn
# cypress/e2e/bdd/user/create.feature
Feature: User Creation
  Scenario: Create a new user
    Given I have valid admin credentials
    When I create a new user with:
      | name  | email               |
      | John  | john.doe@test.com   |
    Then the user should be created successfully
```
#### Step definitions:
```typescript
// cypress/e2e/bdd/user/create.steps.ts
import { Given, When, Then } from '@badeball/cypress-cucumber-preprocessor';
import { ApiClient } from '../../../support/api/client';
import { UserCreateSchema } from '../../../support/api/templates/user';

Given('I have valid admin credentials', () => {
  // Credentials are handled by the auth system
});

When('I create a new user with:', (dataTable) => {
  const userData = dataTable.rowsHash();
  ApiClient.request({
    method: 'POST',
    url: '/api/users',
    schema: UserCreateSchema,
    body: userData,
  }).as('userResponse');
});

Then('the user should be created successfully', () => {
  cy.get('@userResponse').then((response) => {
    expect(response).to.have.property('id');
  });
});
```

## 6. Reporting Configuration
Install reporters:
```bash
npm install mochawesome mochawesome-merge mochawesome-report-generator cypress-multi-reporters --save-dev
```
#### cypress.config.ts
```typescript
export default defineConfig({
  reporter: 'cypress-multi-reporters',
  reporterOptions: {
    reporterEnabled: 'mochawesome',
    mochawesomeReporterOptions: {
      reportDir: 'cypress/reports',
      overwrite: false,
      html: false,
      json: true,
    },
  },
  e2e: {
    // ... other config
  },
});
```
Add script to ```package.json```:
```json
{
  "scripts": {
    "test": "cypress run",
    "merge-reports": "mochawesome-merge cypress/reports/*.json > cypress/reports/combined.json",
    "generate-report": "marge cypress/reports/combined.json --reportDir cypress/reports --inline",
    "full-test": "npm test && npm run merge-reports && npm run generate-report"
  }
}
```


## 7. Example Standard API Test
```cypress/e2e/api/user.spec.ts```:
```typescript
import { ApiClient } from '../../support/api/client';
import { UserCreateSchema, generateUserCreatePayload } from '../../support/api/templates/user';

describe('User API', () => {
  it('should create a new user', () => {
    const userPayload = generateUserCreatePayload({
      name: 'Test User',
      email: 'test.user@example.com',
    });

    ApiClient.request({
      method: 'POST',
      url: '/api/users',
      schema: UserCreateSchema,
      body: userPayload,
    }).then((response) => {
      expect(response).to.have.property('id');
      expect(response.name).to.eq(userPayload.name);
    });
  });

  it('should reject invalid email format', () => {
    const invalidPayload = generateUserCreatePayload({
      email: 'invalid-email',
    });

    cy.request({
      method: 'POST',
      url: '/api/users',
      body: invalidPayload,
      failOnStatusCode: false,
    }).then((response) => {
      expect(response.status).to.eq(400);
    });
  });
});
```

## Key Features of This Framework:
```bash
1. OAuth 2.0 Integration: Automatic token management with refresh logic
2. Type Safety: Zod validation for both requests and responses
3. Test Data Management: Faker-powered template system with override capability
4. Dual Test Formats: Support for both Cucumber BDD and standard tests
5. Comprehensive Reporting: Multiple report formats including HTML and JSON
6. Modular Design: Clean separation of concerns
7. Reusable Components: API client and auth logic can be used across all tests
```

This architecture provides a solid foundation that can be extended for any API testing needs while maintaining clean code organization and robust validation.

# BoilerPlate

## 1. Basic Response Assertions
```typescript
// Basic status and structure validation
export function assertBasicResponse(response: Cypress.Response<any>) {
  expect(response.status).to.be.oneOf([200, 201]); // Common success codes
  expect(response.headers).to.have.property('content-type', 'application/json');
  expect(response.body).to.be.an('object');
}
```
### Example Usage: 
```typescript
cy.request('GET', '/api/users').then((response) => {
  assertBasicResponse(response);
  expect(response.body).to.have.property('data').that.is.an('array');
});
```
## 2. Schema Validation with Zod
```typescript
import { z } from 'zod';

// User schema validation
export function assertUserSchema(data: any) {
  const UserSchema = z.object({
    id: z.string().uuid(),
    name: z.string(),
    email: z.string().email(),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime().optional()
  });
  
  return UserSchema.parse(data); // Throws if invalid
}
```
### Example Usage:
```typescript
cy.request('GET', '/api/users/123').then((response) => {
  const user = assertUserSchema(response.body);
  cy.log(`Validated user: ${user.name}`);
});
```

## 4. Error Response Assertions
```typescript
// Standard error response format
export function assertErrorResponse(
  response: Cypress.Response<any>,
  expectedStatus: number,
  expectedErrorCode: string
) {
  expect(response.status).to.equal(expectedStatus);
  expect(response.body).to.deep.include({
    status: 'error',
    code: expectedErrorCode,
    message: expect.any(String)
  });
  
  if (response.status === 400) {
    expect(response.body).to.have.property('validationErrors').that.is.an('array');
  }
}
```
### Example Usage:
```typescript
cy.request({
  method: 'POST',
  url: '/api/users',
  body: { /* invalid data */ },
  failOnStatusCode: false
}).then((response) => {
  assertErrorResponse(response, 400, 'VALIDATION_ERROR');
});
```

## 5. Array Content Assertions
```typescript
// Validate array contains objects matching schema
export function assertArrayContainsValidItems(
  array: any[],
  validator: (item: any) => void
) {
  expect(array).to.be.an('array').that.is.not.empty;
  array.forEach(item => validator(item));
}
```
### Example Usage:
```typescript
cy.request('GET', '/api/products').then((response) => {
  assertArrayContainsValidItems(response.body.products, (product) => {
    expect(product).to.have.property('id');
    expect(product).to.have.property('price').that.is.a('number').above(0);
  });
});
```

## 8. Database State Assertions
```typescript
// Verify database state after API call
export function assertDatabaseEntry(
  table: string,
  conditions: Record<string, any>,
  expected: Record<string, any>
) {
  cy.task('queryDatabase', { table, conditions }).then((result: any) => {
    expect(result).to.deep.include(expected);
  });
}
```
### Example Usage:
```typescript
const testUser = { name: 'Test', email: 'test@example.com' };

cy.request('POST', '/api/users', testUser).then(() => {
  assertDatabaseEntry('users', { email: testUser.email }, {
    name: testUser.name,
    status: 'active'
  });
});
```
## 9. Partial Object Matching
```typescript
// Validate object contains expected properties
export function assertPartialMatch(
  actual: Record<string, any>,
  expected: Record<string, any>
) {
  Object.keys(expected).forEach(key => {
    expect(actual).to.have.property(key).that.deep.equals(expected[key]);
  });
}
```
### Example Usage:
```typescript
const updateData = { name: 'New Name', status: 'inactive' };

cy.request('PATCH', '/api/users/123', updateData).then((response) => {
  assertPartialMatch(response.body, updateData);
});
```
## 13. Performance Benchmarking
```typescript
// Compare response times between environments
export function assertPerformanceBenchmark(
  requestFn: () => Cypress.Chainable<Cypress.Response<any>>,
  baseline: number,
  threshold = 1.2 // 20% slower allowed
) {
  const startTime = Date.now();
  
  requestFn().then(() => {
    const duration = Date.now() - startTime;
    expect(duration).to.be.lessThan(baseline * threshold);
    cy.log(`Performance: ${duration}ms (baseline: ${baseline}ms)`);
  });
}
```
### Example Usage:
```typescript
const loadDashboard = () => cy.request('GET', '/api/dashboard');

// Compare against 500ms baseline
assertPerformanceBenchmark(loadDashboard, 500); 
```

# Useful Commands
| Command | Description | Example |
|---------|-------------|---------|
| **`cy.request()`** | Makes HTTP requests | `cy.request('GET', '/api/users').then(response => { ... })` |
| **`cy.intercept()`** | Stubs and spies on network requests | `cy.intercept('POST', '/api/login').as('loginRequest')` |
| **`cy.wait()`** | Waits for aliased requests or time | `cy.wait('@loginRequest').its('response.statusCode').should('eq', 200)` |
| **`cy.get()`** | Gets DOM elements | `cy.get('[data-testid="submit-btn"]').click()` |
| **`cy.find()`** | Finds elements within another element | `cy.get('.user-list').find('.user-item')` |
| **`cy.contains()`** | Gets elements containing text | `cy.contains('Login').click()` |
| **`cy.click()`** | Clicks an element | `cy.get('.submit-btn').click()` |
| **`cy.type()`** | Types into input fields | `cy.get('#email').type('test@example.com')` |
| **`cy.clear()`** | Clears input fields | `cy.get('#search').clear()` |
| **`cy.check()`** | Checks checkboxes/radios | `cy.get('#terms').check()` |
| **`cy.uncheck()`** | Unchecks checkboxes | `cy.get('#newsletter').uncheck()` |
| **`cy.select()`** | Selects dropdown options | `cy.get('#country').select('USA')` |
| **`cy.should()`** | Makes assertions | `cy.get('.result').should('contain', 'Success')` |
| **`cy.then()`** | Works with yielded subject | `cy.get('@user').then(user => { ... })` |
| **`cy.wrap()`** | Wraps objects to use Cypress commands | `cy.wrap({ id: 123 }).should('have.property', 'id')` |
| **`cy.its()`** | Gets property from subject | `cy.request(...).its('body.data').should('exist')` |
| **`cy.invoke()`** | Invokes function on subject | `cy.get('.calculator').invoke('add', 2, 3).should('eq', 5)` |
| **`cy.within()`** | Scopes commands to specific element | `cy.get('.modal').within(() => { cy.get('button').click() })` |
| **`cy.each()`** | Iterates through elements | `cy.get('.items').each(item => { ... })` |
| **`cy.log()`** | Outputs to test runner console | `cy.log('Starting test for user creation')` |
| **`cy.fixture()`** | Loads test data from fixtures | `cy.fixture('users.json').then(users => { ... })` |
| **`cy.readFile()`** | Reads file contents | `cy.readFile('cypress/fixtures/data.json')` |
| **`cy.writeFile()`** | Writes to a file | `cy.writeFile('cypress/output/log.txt', 'Test completed')` |
| **`cy.exec()`** | Executes shell commands | `cy.exec('npm run lint')` |
| **`cy.task()`** | Runs Node code in plugins file | `cy.task('queryDB', 'SELECT * FROM users')` |
| **`cy.screenshot()`** | Takes screenshot | `cy.screenshot('login-page')` |
| **`cy.reload()`** | Reloads the page | `cy.reload()` |
| **`cy.go()`** | Goes back/forward in history | `cy.go('back')` |
| **`cy.visit()`** | Visits a URL | `cy.visit('/login')` |
| **`cy.url()`** | Gets current URL | `cy.url().should('include', '/dashboard')` |
| **`cy.hash()`** | Gets URL hash | `cy.hash().should('be.empty')` |
| **`cy.location()`** | Gets window.location | `cy.location('pathname').should('eq', '/login')` |
| **`cy.window()`** | Gets window object | `cy.window().its('localStorage').invoke('getItem', 'token')` |
| **`cy.document()`** | Gets document object | `cy.document().its('title').should('include', 'Home')` |
| **`cy.viewport()`** | Changes viewport size | `cy.viewport(1024, 768)` |
| **`cy.scrollTo()`** | Scrolls to position | `cy.scrollTo('bottom')` |
| **`cy.wait()`** | Waits for time or aliases | `cy.wait(1000)` or `cy.wait('@getUsers')` |
| **`cy.clock()`** | Controls time | `cy.clock().tick(10000)` |
| **`cy.tick()`** | Moves time forward | `cy.clock(); cy.tick(5000)` |
| **`cy.stub()`** | Creates function stubs | `cy.stub(window, 'alert').as('windowAlert')` |
| **`cy.spy()`** | Creates spies on functions | `cy.spy(console, 'log').as('consoleLog')` |
| **`cy.route2()`** (v6+) | Modern network stubbing | `cy.intercept('GET', '/api/users', { fixture: 'users.json' })` |
| **`cy.session()`** | Caches and restores sessions | `cy.session('user', () => { login() })` |
| **`cy.origin()`** | Cross-origin testing | `cy.origin('https://auth.site.com', () => { ... })` |
| **`cy.focused()`** | Gets focused element | `cy.get('#username').type('test').focused().blur()` |
| **`cy.blur()`** | Removes focus from element | `cy.get('#search').type('test').blur()` |
| **`cy.hover()`** | Hovers over element | `cy.get('.menu-item').hover()` |
| **`cy.trigger()`** | Triggers DOM events | `cy.get('.btn').trigger('mouseover')` |
| **`cy.selectFile()`** | Selects files for upload | `cy.get('input[type="file"]').selectFile('cypress/fixtures/photo.jpg')` |
| **`cy.clearCookies()`** | Clears browser cookies | `cy.clearCookies()` |
| **`cy.clearLocalStorage()`** | Clears localStorage | `cy.clearLocalStorage()` |
| **`cy.pause()`** | Pauses test execution | `cy.pause()` |
| **`cy.debug()`** | Debugs at current step | `cy.get('#element').debug()` |
| **`cy.focused()`** | Gets focused element | `cy.focused().should('have.id', 'username')` |
| **`cy.root()`** | Gets root DOM element | `cy.root().should('match', 'html')` |
| **`cy.as()`** | Creates alias for later use | `cy.get('.user').as('currentUser')` |
| **`cy.realClick()`** | Real click (from cypress-real-events) | `cy.get('.dropdown').realClick()` |
| **`cy.realType()`** | Real typing (from cypress-real-events) | `cy.get('#input').realType('Hello{enter}')` |

### Usage Notes:
```markdown
1. Network Commands: cy.request(), cy.intercept(), and cy.wait() are essential for API testing
2. DOM Commands: cy.get(), cy.find(), cy.contains() for UI interactions
3. Assertion Commands: should(), then(), its() for validation
4. Utility Commands: cy.wrap(), cy.log(), cy.fixture() for test organization
5. Advanced Commands: cy.session(), cy.origin() for complex scenarios
```

# Database Queries

## 1. Database Connection Setup (Node.js plugin)
`cypress/plugins/index.js:`
```typescript
const mysql = require('mysql2/promise'); // or your DB client

module.exports = (on, config) => {
  on('task', {
    async queryDB({ query, values = [] }) {
      const db = await mysql.createConnection({
        host: config.env.dbHost,
        user: config.env.dbUser,
        password: config.env.dbPassword,
        database: config.env.dbName
      });
      const [rows] = await db.execute(query, values);
      await db.end();
      return rows;
    }
  });
};
```
## 2. Database Assertion Utilities
`cypress/support/db-assertions.js:`

```javascript
// Compare API response with database record
export function assertDbRecord(table, apiResponse, fieldMap = {}) {
  const id = apiResponse.id || apiResponse.data.id;
  const query = `SELECT * FROM ${table} WHERE id = ?`;
  
  cy.task('queryDB', { query, values: [id] }).then(dbRecords => {
    expect(dbRecords.length).to.eq(1, `Should find 1 record in ${table} for ID ${id}`);
    
    const dbRecord = dbRecords[0];
    const fieldsToCheck = Object.keys(fieldMap).length ? fieldMap : apiResponse;
    
    Object.entries(fieldsToCheck).forEach(([apiField, dbField]) => {
      const actualDbField = typeof dbField === 'string' ? dbField : apiField;
      const apiValue = apiResponse[apiField];
      const dbValue = dbRecord[actualDbField];
      
      // Handle special cases like date comparisons
      if (dbValue instanceof Date) {
        expect(new Date(apiValue).to.deep.eq(dbValue, `Field ${apiField} should match`);
      } else {
        expect(apiValue).to.deep.eq(
          dbValue,
          `API field "${apiField}" should match DB field "${actualDbField}"`
        );
      }
    });
  });
}

// Verify record count after operation
export function assertRecordCount(table, expectedCount, conditions = {}) {
  let whereClause = '';
  const values = [];
  
  if (Object.keys(conditions).length) {
    whereClause = ' WHERE ' + Object.keys(conditions)
      .map(field => {
        values.push(conditions[field]);
        return `${field} = ?`;
      })
      .join(' AND ');
  }
  
  const query = `SELECT COUNT(*) as count FROM ${table}${whereClause}`;
  
  cy.task('queryDB', { query, values }).then(result => {
    expect(result[0].count).to.eq(expectedCount);
  });
}
```

## 3. Example Test Usage
### Scenario 1: Verify Created Record
```javascript
import { assertDbRecord } from '../support/db-assertions';

describe('User API', () => {
  it('creates a user and verifies database', () => {
    const userData = {
      name: 'Test User',
      email: 'test@example.com'
    };

    cy.request('POST', '/api/users', userData).then(apiResponse => {
      // Verify API response
      expect(apiResponse.status).to.eq(201);
      
      // Map API fields to DB columns if they differ
      assertDbRecord('users', apiResponse.body, {
        name: 'user_name', // API field 'name' maps to DB column 'user_name'
        email: 'email_address'
      });
    });
  });
});
```
### Scenario 2: Verify Deleted Record
```javascript
import { assertRecordCount } from '../support/db-assertions';

it('deletes a user and verifies database', () => {
  const userId = 123;
  
  cy.request('DELETE', `/api/users/${userId}`).then(() => {
    assertRecordCount('users', 0, { id: userId });
  });
});
```

### Scenario 3: Verify Updated Record
```javascript
it('updates user and checks database', () => {
  const updateData = { status: 'inactive' };
  
  cy.request('PATCH', '/api/users/456', updateData).then(apiResponse => {
    assertDbRecord('users', apiResponse.body, {
      status: 'account_status' // Maps API field to DB column
    });
    
    // Additional verification of updated timestamp
    cy.task('queryDB', {
      query: 'SELECT updated_at FROM users WHERE id = ?',
      values: [apiResponse.body.id]
    }).then(([record]) => {
      const dbUpdatedTime = new Date(record.updated_at).getTime();
      const apiUpdatedTime = new Date(apiResponse.body.updatedAt).getTime();
      expect(apiUpdatedTime).to.be.closeTo(dbUpdatedTime, 1000); // Within 1 second
    });
  });
});
```

## 4. Advanced Database Validations
### Transaction Verification
```javascript
export function verifyTransaction(apiResponse) {
  const transactionId = apiResponse.transactionId;
  
  // Check transactions table
  cy.task('queryDB', {
    query: `SELECT * FROM transactions WHERE id = ?`,
    values: [transactionId]
  }).then(transactions => {
    expect(transactions.length).to.eq(1);
    
    // Check related records in junction table
    cy.task('queryDB', {
      query: `SELECT COUNT(*) as count FROM user_transactions WHERE transaction_id = ?`,
      values: [transactionId]
    }).then(result => {
      expect(result[0].count).to.be.greaterThan(0);
    });
  });
}
```
### Soft Delete Verification
```javascript
export function verifySoftDelete(table, id) {
  cy.task('queryDB', {
    query: `SELECT deleted_at FROM ${table} WHERE id = ?`,
    values: [id]
  }).then(([record]) => {
    expect(record.deleted_at).to.not.be.null;
    expect(new Date(record.deleted_at)).to.be.closeTo(new Date(), 10000); // Within 10 seconds
  });
}
```
## 5. Configuration
`cypress.config.js:`

```javascript
module.exports = defineConfig({
  env: {
    dbHost: 'localhost',
    dbUser: 'testuser',
    dbPassword: 'testpass',
    dbName: 'testdb'
  },
  // ... other config
});
```

## Key Features:
```
- Flexible Field Mapping: Handles different field names between API and DB
- Type Conversion: Automatically handles date comparisons
- Transaction Support: Verifies complex operations across multiple tables
- Count Verification: Validates record creation/deletion counts
- Soft Delete Support: Special handling for deleted_at fields
- Environment Config: Secure credential management
```
### Usage Tips:
```
- For sensitive data: Use cypress.env.json for database credentials
- For complex queries: Create custom task handlers in the plugin file
- For performance: Add query timeouts in your DB connection
- For CI/CD: Configure different DB credentials per environment

This boilerplate provides a solid foundation for API-database integration testing that you can extend for your specific database schema and API structure.
```

