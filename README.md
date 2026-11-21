# DIDOU PHONE — Updated Store

A mobile-friendly Algerian smartphone storefront with customer accounts and a protected admin console.

## Features
- Premium responsive home page, brand filtering, search and product details
- Product catalog, pricing in DZD, stock and featured products
- Shopping cart and cash-on-delivery checkout
- Customer registration and sign-in (email + password)
- Customer profile: name, phone, wilaya and delivery address
- Change password while signed in
- Personal order history and order status
- Admin dashboard: summary, product CRUD, order status management and customer account list
- Server-side stock checks and hashed passwords

## Deploy to Render
This project is a Node.js app; do not open `index.html` directly. Deploy the repository as a Render Blueprint using `render.yaml` or as a Node web service.

Set environment variables:
- `ADMIN_USERNAME`: admin login name
- `ADMIN_PASSWORD`: strong password, at least 12 characters
- `SESSION_SECRET`: long random secret (Render Blueprint generates it)
- `NODE_ENV`: production
- `NODE_VERSION`: 20.19.0

The project requires Node.js 20.x. `package.json` pins the supported major version.

## Important data storage note
This starter uses SQLite. On hosting without a persistent disk, the database may reset after redeploy/restart; registered accounts, products and orders can be lost. For a real production store, attach persistent storage or migrate the database to a managed PostgreSQL service before accepting real customer orders.

## Admin
Open `/admin.html` after deployment and sign in using `ADMIN_USERNAME` and `ADMIN_PASSWORD` set in Render. The admin user is created when the server starts with these variables configured.

## Customer account
Customers can create an account from the **Sign in** button on the storefront. Passwords are hashed. Password change is available after login. Email-based password recovery is not included because it requires an email delivery provider and verification flow.


## Languages
The storefront includes an Arabic / French / English language selector. Arabic uses RTL layout. The selected language is saved in the browser. The selector translates common storefront, account, cart, checkout and status labels; product names and user-entered product descriptions remain as entered by the admin.
