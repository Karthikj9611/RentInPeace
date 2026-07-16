// ══════════════════════════════════════════════
// MAIL MODULE
// All email sending logic (Brevo/Sendinblue transport + HTML templates)
// lives here, separate from server.js.
//
// Required .env variable:
//   BREVO_API_KEY - Brevo (Sendinblue) email API key
// ══════════════════════════════════════════════

const axios = require("axios");

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_SENDER_EMAIL = "karthik.j@enhancesys.com";
const BREVO_SENDER_NAME = "KR Real Estate";

// ── HTML escape helper for email templates ──
function escHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── Low-level transport: send an email via Brevo's API ──
async function sendEmailWithBrevo(to, subject, htmlContent) {
  try {
    const response = await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { email: BREVO_SENDER_EMAIL, name: BREVO_SENDER_NAME },
        to: [{ email: to, name: to.split('@')[0] }],
        subject: subject,
        htmlContent: htmlContent
      },
      {
        headers: {
          "Content-Type": "application/json",
          "api-key": BREVO_API_KEY
        }
      }
    );
    return { success: true, data: response.data };
  } catch (error) {
    console.error("Brevo email error:", error.response?.data || error.message);
    return { success: false, error: error.response?.data || error.message };
  }
}

// ── Template: OTP verification email ──
function otpEmailTemplate(otp) {
  return `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e0e0e0">
    <div style="background:linear-gradient(135deg,#1b3a2d,#2e7d5a);padding:22px 24px;text-align:center">
      <h2 style="margin:0;color:#fff;font-size:1.4rem">KR Real Estate</h2>
      <p style="margin:4px 0 0;color:rgba(255,255,255,0.6);font-size:0.8rem">Email Verification</p>
    </div>
    <div style="padding:28px 24px;text-align:center">
      <p style="color:#555;margin-bottom:18px">Your One-Time Password:</p>
      <div style="font-size:2.4rem;font-weight:800;letter-spacing:10px;background:#f0f9f4;padding:16px 20px;border-radius:10px;display:inline-block;color:#1b3a2d;border:2px dashed #2e7d5a">${otp}</div>
      <p style="color:#999;font-size:0.8rem;margin-top:16px">Valid for <strong>5 minutes</strong>. Do not share this OTP.</p>
    </div>
    <div style="background:#f9f9f9;padding:12px;text-align:center;font-size:0.72rem;color:#bbb">
      © ${new Date().getFullYear()} KR Real Estate
    </div>
  </div>`;
}

// ── Template: Appointment confirmation email ──
function appointmentConfirmedEmailTemplate(appt) {
  const slotIcon = { Morning: '🌅', Afternoon: '☀️', Evening: '🌙' }[appt.timeSlot] || '🕐';
  return `
<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;background:#fff;border-radius:14px;overflow:hidden;border:1px solid #e0e0e0">
  <div style="background:linear-gradient(135deg,#1b3a2d,#2e7d5a);padding:24px;text-align:center">
    <h2 style="margin:0;color:#fff;font-size:1.4rem;font-family:Georgia,serif">KR Real Estate</h2>
    <p style="margin:6px 0 0;color:rgba(255,255,255,0.7);font-size:0.82rem">Appointment Confirmed</p>
  </div>
  <div style="padding:30px 28px">
    <p style="font-size:1rem;color:#222;margin-bottom:6px">Hi <strong>${escHtml(appt.name)}</strong>,</p>
    <p style="color:#555;font-size:0.9rem;line-height:1.6;margin-bottom:24px">
      Your appointment with <strong>KR Real Estate</strong> has been <span style="color:#1a7a5e;font-weight:700">confirmed</span>. Here are your details:
    </p>
    <div style="background:#f4f9f6;border-radius:10px;padding:18px 20px;border:1px solid #d0ece1;margin-bottom:24px">
      <table style="width:100%;border-collapse:collapse;font-size:0.88rem">
        <tr><td style="padding:7px 0;color:#666;width:40%">📅 Date</td><td style="padding:7px 0;font-weight:700;color:#111">${escHtml(appt.date)}</td></tr>
        <tr><td style="padding:7px 0;color:#666">${slotIcon} Time Slot</td><td style="padding:7px 0;font-weight:700;color:#111">${escHtml(appt.timeSlot)}</td></tr>
        <tr><td style="padding:7px 0;color:#666">🏠 Purpose</td><td style="padding:7px 0;font-weight:700;color:#111">${escHtml(appt.purpose)}</td></tr>
        <tr><td style="padding:7px 0;color:#666">📞 Mobile</td><td style="padding:7px 0;font-weight:700;color:#111">${escHtml(appt.mobile)}</td></tr>
        ${appt.message ? `<tr><td style="padding:7px 0;color:#666;vertical-align:top">💬 Message</td><td style="padding:7px 0;color:#333">${escHtml(appt.message)}</td></tr>` : ''}
      </table>
    </div>
    <p style="color:#555;font-size:0.85rem;line-height:1.7;margin-bottom:20px">
      Our team will be in touch if there are any changes. For queries, feel free to reply to this email or call us directly.
    </p>
    <div style="text-align:center">
      <a href="tel:${escHtml(appt.mobile)}" style="display:inline-block;background:#1b3a2d;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-size:0.88rem;font-weight:700">📞 Contact Us</a>
    </div>
  </div>
  <div style="background:#f9f9f9;padding:14px;text-align:center;font-size:0.72rem;color:#aaa">
    © ${new Date().getFullYear()} KR Real Estate · This is an automated message
  </div>
</div>`;
}

module.exports = {
  sendEmailWithBrevo,
  escHtml,
  otpEmailTemplate,
  appointmentConfirmedEmailTemplate
};
