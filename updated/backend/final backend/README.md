# Email OTP Verification using Node.js

## Overview

This is a simple Node.js application that demonstrates email OTP (One-Time Password) verification. The application generates a unique OTP and sends it to the user's email address for verification.

## Features

- Generate and send OTP via email.
- Verify the OTP entered by the user.
- Simple and easy-to-understand Node.js implementation.

## Requirements

- Node.js installed on your machine.
- NPM (Node Package Manager) installed.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/srivarshithdaladuli/Email-OTP-Verification.git
   ```

2. Navigate to the project directory:

   ```bash
   cd Email-Otp-Verification
   ```

3. Install the dependencies:

   ```bash
   npm install
   ```

4. Create a `.env` file in the root directory and add the following configurations:

   ```env
   EMAIL_USERNAME=your_email@gmail.com
   EMAIL_PASSWORD=your_email_password
   ```

   Replace `your_email@gmail.com` with your Gmail address and `your_email_password` with your Gmail password. Note that using your actual email credentials in production is not recommended; consider using an app-specific password for increased security.

5. Start the application:

   ```bash
   npm start
   ```

6. Open your browser and go to [http://localhost:3000](http://localhost:3000) to access the application.

## Usage

1. Open your browser and go to [http://localhost:3000](http://localhost:3000).
2. Enter your email address and click on the "Send OTP" button.
3. Check your email inbox for the OTP.
4. Enter the OTP in the provided input field and click on the "Verify OTP" button.
5. You will receive a success message if the OTP is correct.


## Contributing

Feel free to contribute to this project by submitting pull requests or opening issues.

## License

This project is licensed under the [MIT License](https://github.com/srivarshithdaladuli/Email-OTP-Verification/blob/master/LICENSE).

---

Happy coding!
