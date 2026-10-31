import React, { useState } from 'react';
import { MessageSquare, Send, Sparkles, CheckCircle2, Cpu } from './Icons';

export default function AICopilot({ scanData }) {
  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: 'مرحباً بك! أنا المساعد الأمني الذكي لنظام AI-CSPM (Security Copilot). يمكنك سؤالي عن مسار الهجوم المكتشف، أو سبب عجز الأدوات التقليدية (مثل Prowler)، أو كيفية عمل كود العلاج التلقائي.',
      citedNodes: ['AI-CSPM Graph Engine']
    }
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const quickPrompts = [
    'هل تستطيع حاوية الدفع فك تشفير بيانات العملاء؟',
    'لماذا أعطت أداة Prowler تقييم PASS للثغرة؟',
    'كيف يقلص كود الـ AI مساحة الهجوم إلى 99.9%؟',
    'اشرح مسار الهجوم للمشرف بلغة هندسية سريعة'
  ];

  const handleSend = async (queryToSend) => {
    const q = queryToSend || inputQuery;
    if (!q.trim()) return;

    // Add user message
    setMessages(prev => [...prev, { sender: 'user', text: q }]);
    setInputQuery('');
    setLoading(true);

    try {
      const resp = await fetch('http://127.0.0.1:8000/api/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q })
      });

      if (resp.ok) {
        const data = await resp.json();
        setMessages(prev => [...prev, {
          sender: 'ai',
          text: data.answer_ar,
          citedNodes: data.cited_nodes || []
        }]);
      } else {
        throw new Error('API response error');
      }
    } catch (err) {
      // Local intelligent response fallback
      let fallbackText = 'بناءً على تحليل الرسم البياني السياقي، ترتبط الحاوية في كوبرنيتس بالدور السحابي eks-payment-kms-role الذي يحمل سياسة فك تشفير شاملة (*) لكافة مفاتيح KMS، مما يتيح تسريب بيانات خزانة S3 بالكامل.';
      if (q.includes('prowler') || q.includes('pass')) {
        fallbackText = 'أداة Prowler فحصت الـ Role بمعزل عن الحاوية وبحثت فقط عن *:* أو kms:*. ولأن السياسة محددة بـ kms:Decrypt اعتبرتها آمنة ومنحتها [PASS] 100% متجاهلة المورد الشامل (*).';
      } else if (q.includes('99.9') || q.includes('علاج')) {
        fallbackText = 'قام الذكاء الاصطناعي بحصر فك التشفير على مفتاح الدفع الفعلي (aws_kms_key.payment_key.arn) وإضافة شرط EncryptionContext لخزانة S3، مما قيد الصلاحيات لمفتاح واحد فقط من أصل مئات المفاتيح في الحساب.';
      }
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: fallbackText,
        citedNodes: ['Contextual Graph Fallback']
      }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Sparkles size={20} color="#38bdf8" />
            AI Security Copilot (المساعد الأمني الذكي لبيئة السحابة)
          </h2>
          <p style={{ fontSize: 13, color: '#94a3b8' }}>
            تفاعل مع الذكاء الاصطناعي باللغة العربية واسأله عن تفاصيل مسار الهجوم وسبب فشل الأدوات الأخرى.
          </p>
        </div>
      </div>

      {/* Quick Prompts */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
        {quickPrompts.map((prompt, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(prompt)}
            disabled={loading}
            style={{
              background: '#0f172a',
              border: '1px solid #334155',
              color: '#38bdf8',
              padding: '6px 12px',
              borderRadius: 20,
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}
          >
            💬 {prompt}
          </button>
        ))}
      </div>

      {/* Chat Messages Box */}
      <div style={{
        background: '#070a12',
        border: '1px solid #1e293b',
        borderRadius: 12,
        padding: 20,
        minHeight: 380,
        maxHeight: 480,
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column',
        gap: 14
      }}>
        {messages.map((m, idx) => (
          <div
            key={idx}
            style={{
              alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
              maxWidth: '85%',
              background: m.sender === 'user' ? 'linear-gradient(135deg, #0284c7, #2563eb)' : '#0f172a',
              border: m.sender === 'user' ? 'none' : '1px solid #334155',
              color: '#f8fafc',
              padding: '12px 18px',
              borderRadius: 12,
              fontSize: 13,
              lineHeight: 1.6,
              direction: 'rtl'
            }}
          >
            <div style={{ whiteSpace: 'pre-line' }}>{m.text}</div>

            {m.citedNodes && m.citedNodes.length > 0 && (
              <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 6, direction: 'ltr' }}>
                {m.citedNodes.map((n, i) => (
                  <span
                    key={i}
                    style={{
                      background: 'rgba(56, 189, 248, 0.15)',
                      color: '#38bdf8',
                      fontSize: 10,
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 4
                    }}
                  >
                    🏷️ {n}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div style={{
            alignSelf: 'flex-start',
            background: '#0f172a',
            border: '1px solid #334155',
            color: '#38bdf8',
            padding: '10px 16px',
            borderRadius: 12,
            fontSize: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 8
          }}>
            <Cpu size={16} className="spin-icon" />
            جاري استرجاع العلاقات من الرسم البياني والتحليل بالذكاء الاصطناعي...
          </div>
        )}
      </div>

      {/* Input Bar */}
      <form
        onSubmit={(e) => { e.preventDefault(); handleSend(); }}
        style={{ display: 'flex', gap: 10, marginTop: 14 }}
      >
        <input
          type="text"
          value={inputQuery}
          onChange={(e) => setInputQuery(e.target.value)}
          placeholder="اكتب سؤالك الأمني هنا للمشرف أو للتحقق من أي نقطة..."
          style={{
            flex: 1,
            background: '#0f172a',
            border: '1px solid #334155',
            color: '#f8fafc',
            padding: '12px 16px',
            borderRadius: 10,
            fontSize: 13,
            direction: 'rtl'
          }}
        />
        <button
          type="submit"
          disabled={loading}
          className="btn-primary"
          style={{ padding: '0 20px' }}
        >
          <Send size={16} />
          إرسال
        </button>
      </form>
    </div>
  );
}
