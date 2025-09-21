const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { query } = require("../config/database")
const { validate, schemas } = require("../middleware/validation")
const { authenticateToken } = require("../middleware/auth")

const router = express.Router()

// تسجيل الدخول
router.post("/login", validate(schemas.login), async (req, res) => {
  try {
    const { username, password } = req.body

    // البحث عن المستخدم
    const result = await query(
      "SELECT id, username, email, password_hash, first_name, last_name, role, is_active FROM users WHERE username = $1 OR email = $1",
      [username],
    )

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "اسم المستخدم أو كلمة المرور غير صحيحة",
      })
    }

    const user = result.rows[0]

    // التحقق من حالة الحساب
    if (!user.is_active) {
      return res.status(401).json({
        success: false,
        message: "الحساب غير مفعل",
      })
    }

    // التحقق من كلمة المرور
    const isValidPassword = await bcrypt.compare(password, user.password_hash)
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: "اسم المستخدم أو كلمة المرور غير صحيحة",
      })
    }

    // إنشاء التوكن
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE },
    )

    // تحديث وقت آخر دخول
    await query("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", [user.id])

    // إرسال الاستجابة
    res.json({
      success: true,
      message: "تم تسجيل الدخول بنجاح",
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          first_name: user.first_name,
          last_name: user.last_name,
          role: user.role,
        },
      },
    })
  } catch (error) {
    console.error("خطأ في تسجيل الدخول:", error)
    res.status(500).json({
      success: false,
      message: "خطأ في الخادم",
    })
  }
})

// تسجيل الخروج
router.post("/logout", authenticateToken, async (req, res) => {
  try {
    // في التطبيق الحقيقي، يمكن إضافة التوكن إلى قائمة سوداء
    res.json({
      success: true,
      message: "تم تسجيل الخروج بنجاح",
    })
  } catch (error) {
    console.error("خطأ في تسجيل الخروج:", error)
    res.status(500).json({
      success: false,
      message: "خطأ في الخادم",
    })
  }
})

// التحقق من صحة التوكن
router.get("/verify", authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      message: "التوكن صحيح",
      data: {
        user: req.user,
      },
    })
  } catch (error) {
    console.error("خطأ في التحقق من التوكن:", error)
    res.status(500).json({
      success: false,
      message: "خطأ في الخادم",
    })
  }
})

// تغيير كلمة المرور
router.put("/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور الحالية والجديدة مطلوبتان",
      })
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل",
      })
    }

    // الحصول على كلمة المرور الحالية
    const result = await query("SELECT password_hash FROM users WHERE id = $1", [req.user.id])

    const user = result.rows[0]

    // التحقق من كلمة المرور الحالية
    const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash)
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: "كلمة المرور الحالية غير صحيحة",
      })
    }

    // تشفير كلمة المرور الجديدة
    const hashedNewPassword = await bcrypt.hash(newPassword, 12)

    // تحديث كلمة المرور
    await query("UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", [
      hashedNewPassword,
      req.user.id,
    ])

    res.json({
      success: true,
      message: "تم تغيير كلمة المرور بنجاح",
    })
  } catch (error) {
    console.error("خطأ في تغيير كلمة المرور:", error)
    res.status(500).json({
      success: false,
      message: "خطأ في الخادم",
    })
  }
})

module.exports = router
