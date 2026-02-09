# REFUND & CANCELLATION QUICK REFERENCE

## 🚀 QUICK START

### **For Customers**
```
Order Tracking Page:
├─ Cancel Product Button (Active items only)
│  └─ Modal confirms + asks reason
│     └─ Email to customer & admin
│
└─ Refund Button (Delivered items only)
   └─ Modal asks reason
      └─ Email to customer & admin
```

### **For Admins**
```
Orders → Order Products Admin:
├─ Quick Actions
│  ├─ Approve selected refund requests
│  └─ Approve selected cancellation requests
│
├─ Filters
│  ├─ By refund_status
│  └─ By cancellation_status
│
└─ Detailed View
   ├─ Edit refund_status
   └─ Edit cancellation_status
```

---

## 📊 STATUS FLOW

### **Refund Status**
```
No Request → Requested → Approved/Rejected
```

### **Cancellation Status**
```
Active → Cancellation Requested → Cancelled
```

---

## 📧 EMAILS SENT

| Event | To | Purpose |
|-------|----|---------| 
| Customer requests refund | Customer | Confirm receipt, show timeline |
| Customer requests refund | Admin | Alert for review |
| Customer requests cancel | Customer | Confirm receipt, show timeline |
| Customer requests cancel | Admin | Alert for review |

---

## 🔑 KEY FIELDS

### **OrderProduct Model**
```python
refund_status = CharField(choices=[
    'No Request', 'Requested', 'Approved', 'Rejected'
])
cancellation_status = CharField(choices=[
    'Active', 'Cancellation Requested', 'Cancelled'
])
refund_reason = TextField(blank=True)
cancellation_reason = TextField(blank=True)
refund_requested_at = DateTimeField(null=True)
cancellation_requested_at = DateTimeField(null=True)
```

---

## 🎯 RULES

### **Refund**
✅ Available if: Order is 'Completed' OR Product is 'Delivered'
✅ Only show if: No existing refund request
✅ Button shows: Only on delivered products

### **Cancellation**
✅ Available if: Product not yet cancelled
✅ Only show if: Cancellation not already requested
✅ Button shows: Only on active products

---

## 💻 API ENDPOINTS

```
POST /orders/request_refund/
├─ data: {
│   'order_product_id': 123,
│   'reason': 'text'
│ }
└─ return: {'success': bool, 'message': str}

POST /orders/request_cancellation/
├─ data: {
│   'order_product_id': 123,
│   'reason': 'text'
│ }
└─ return: {'success': bool, 'message': str}
```

---

## 🛠️ ADMIN ACTIONS

### **Quick Actions**
```
Refund:
- Approve selected refund requests
- Reject selected refund requests

Cancellation:
- Approve selected cancellation requests
```

### **Manual Approval**
```
1. Click product in list
2. Scroll to section
3. Edit status field
4. Save
```

---

## 📧 EMAIL TEMPLATE LOCATIONS

```
templates/orders/
├─ refund_request_email.html (Customer)
├─ refund_request_admin_email.html (Admin)
├─ cancellation_request_email.html (Customer)
└─ cancellation_request_admin_email.html (Admin)
```

---

## 🔐 SECURITY

✅ User authentication required
✅ Order ownership verified
✅ CSRF token validation
✅ Status validation on server
✅ Error handling graceful

---

## 📱 UI ELEMENTS

### **Order Tracking Page**
```
Product Card:
├─ Product image
├─ Product name & quantity
├─ Status badges:
│  ├─ Refund: [Status]
│  └─ [Cancellation Status]
└─ Buttons (if eligible):
   ├─ Cancel Product (red)
   └─ Refund (green)
```

### **Modals**
```
Cancellation Modal:
├─ Warning message
├─ Product name
├─ Reason textarea
└─ Confirm button

Refund Modal:
├─ Instruction message
├─ Product name
├─ Reason textarea
└─ Confirm button
```

---

## 📊 ADMIN LIST VIEW

```
OrderProduct List:
├─ Columns:
│  ├─ Order
│  ├─ Product
│  ├─ User
│  ├─ Quantity
│  ├─ Price
│  ├─ Refund Status ← NEW
│  ├─ Cancellation Status ← NEW
│  ├─ Ordered
│  └─ Created At
│
├─ Filters:
│  ├─ By ordered
│  ├─ By refund_status ← NEW
│  ├─ By cancellation_status ← NEW
│  └─ By created_at
│
└─ Actions:
   ├─ Approve refund requests ← NEW
   ├─ Reject refund requests ← NEW
   └─ Approve cancellation requests ← NEW
```

---

## 🔧 TESTING

```
Customer Flow:
1. Go to order tracking
2. Click refund/cancel button
3. Fill modal
4. Confirm
5. Check success message
6. Check email
7. Check status badge updated

Admin Flow:
1. Go to OrderProduct admin
2. Filter by status
3. Use quick action OR edit details
4. Save
5. Verify status updated
```

---

## 🚀 FILES

### **Created**
- `REFUND_CANCELLATION_GUIDE.md` (This guide)
- `templates/orders/refund_request_email.html`
- `templates/orders/cancellation_request_email.html`
- `templates/orders/refund_request_admin_email.html`
- `templates/orders/cancellation_request_admin_email.html`
- `orders/migrations/0006_orderproduct_cancellation_reason_and_more.py`

### **Modified**
- `orders/models.py` (6 new fields added)
- `orders/views.py` (2 new functions + imports)
- `orders/urls.py` (2 new endpoints)
- `orders/admin.py` (Enhanced OrderProductAdmin)
- `templates/orders/order_tracking.html` (UI + JS)

---

## 📞 COMMON TASKS

### **Process a Refund Request**
```
1. Orders → Order Products → Filter "Requested"
2. Click order product
3. Review reason
4. Change refund_status to "Approved" or "Rejected"
5. Save
```

### **Process a Cancellation Request**
```
1. Orders → Order Products → Filter "Cancellation Requested"
2. Click order product
3. Check shipping status
4. Click "Approve selected cancellation requests"
5. Confirm
```

### **Bulk Approve Refunds**
```
1. Orders → Order Products
2. Filter "refund_status = Requested"
3. Select checkboxes
4. Choose "Approve selected refund requests"
5. Click "Go"
```

---

## 🎯 STATUS REFERENCE

| What | Values | Default |
|-----|--------|---------|
| Refund Status | No Request, Requested, Approved, Rejected | No Request |
| Cancellation | Active, Cancellation Requested, Cancelled | Active |

---

## ✨ FEATURES AT A GLANCE

| Feature | Status |
|---------|--------|
| Customer refund request | ✅ Implemented |
| Customer cancellation request | ✅ Implemented |
| Confirmation dialogs | ✅ Implemented |
| Reason collection | ✅ Implemented |
| Email notifications | ✅ Implemented |
| Admin approval UI | ✅ Implemented |
| Bulk actions | ✅ Implemented |
| Status tracking | ✅ Implemented |
| Security | ✅ Implemented |
| Mobile responsive | ✅ Implemented |

---

**Server:** http://127.0.0.1:1111  
**Admin:** http://127.0.0.1:1111/adminsafe/  
**Status:** ✅ LIVE & READY
