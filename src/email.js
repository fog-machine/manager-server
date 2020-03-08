const nodemailer = require('nodemailer');
let config;

exports.setup = (program) => {
  config = program.email;
}

exports.sendMessage = async (sendTo, subject, message, messageHTML) => {
  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: false, // true for 465, false for other ports
    auth: {
      user: config.user, 
      pass: config.password
    }, 
    tls: {
      rejectUnauthorized: false
    }
  });

  try {
    const info = await transporter.sendMail({
      from: `"${config.from}" <${config.user}>`,
      to: sendTo,
      subject: subject,
      text: message,
      html: messageHTML
    });

    console.log("Message sent: %s", info.messageId);
  } catch (err) {
    console.log(err)
  }
}

