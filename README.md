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
