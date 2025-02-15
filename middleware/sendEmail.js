const nodeMail = require("nodemailer");

exports.sendEmail = async (options) => {
    try{

  const transporter = nodeMail.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
      user: process.env.SMTP_EMAIL,
      pass: process.env.SMTP_PASSWORD,
    },
    service: process.env.SMTP_SERVICE,
  });
  const mailOptions = {
    from: process.env.SMTP_EMAIL,
    to: options.email,
    subject: options.subject,
    text: options.message,
  };
  console.log({ transporter });
  console.log({ mailOptions });

  await transporter.sendMail(mailOptions);
}
catch(error){
    console.log(error);
}
};
