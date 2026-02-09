# SYSTEM ARCHITECTURE - REFUND & CANCELLATION

## 🏗️ COMPONENT DIAGRAM

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CUSTOMER INTERFACE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Order Tracking Page (order_tracking.html)                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      Product Item Card                        │  │
│  │  ┌──────────┐  Product Name         $99.99                  │  │
│  │  │          │  Qty: 1                                        │  │
│  │  │ Product  │  [Refund: Requested] [Cancelled]              │  │
│  │  │ Image    │                                                │  │
│  │  │          │  [Cancel Product] [Refund]  ← Buttons         │  │
│  │  └──────────┘                                                │  │
│  │                                                               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  Modal Dialogs (Bootstrap)                                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 💰 Request Refund                          [✕]              │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │ Reason: [                                                  ] │  │
│  │         [Optional text]                                      │  │
│  │ [Cancel] [Request Refund]                                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ ⚠️  Confirm Product Cancellation          [✕]              │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │ Reason: [                                                  ] │  │
│  │         [Optional text]                                      │  │
│  │ [Cancel] [Yes, Cancel Product]                              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
                        JavaScript Handler
                              ↓
                   Collect data & validate
                              ↓
                  AJAX POST Request
                    (with CSRF token)
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      DJANGO BACKEND                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  URL Router (urls.py)                                               │
│  ├─ POST /orders/request_refund/         → request_refund view     │
│  └─ POST /orders/request_cancellation/   → request_cancellation v. │
│                                                                       │
│  Views (views.py)                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ request_refund(request):                                     │  │
│  │  1. Parse JSON body                                          │  │
│  │  2. Get OrderProduct                                         │  │
│  │  3. Validate user ownership                                  │  │
│  │  4. Check refund_status == 'No Request'                      │  │
│  │  5. Update: refund_status = 'Requested'                      │  │
│  │  6. Call send_refund_request_email()                         │  │
│  │  7. Return JSON response                                     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ request_cancellation(request):                               │  │
│  │  1. Parse JSON body                                          │  │
│  │  2. Get OrderProduct                                         │  │
│  │  3. Validate user ownership                                  │  │
│  │  4. Check cancellation_status == 'Active'                    │  │
│  │  5. Update: cancellation_status = 'Canc. Requested'          │  │
│  │  6. Call send_cancellation_request_email()                   │  │
│  │  7. Return JSON response                                     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  Models (models.py)                                                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ OrderProduct (Enhanced)                                      │  │
│  │  - refund_status: CharField(choices=[...])                   │  │
│  │  - cancellation_status: CharField(choices=[...])             │  │
│  │  - refund_reason: TextField(null, blank)                     │  │
│  │  - cancellation_reason: TextField(null, blank)               │  │
│  │  - refund_requested_at: DateTimeField(null)                  │  │
│  │  - cancellation_requested_at: DateTimeField(null)            │  │
│  │                                                               │  │
│  │ Tables Updated:                                              │  │
│  │  ├─ orders_orderproduct (6 new columns)                      │  │
│  │  └─ Migration: 0006_orderproduct_...                         │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  Email System (Email Handler)                                        │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ send_refund_request_email(order_product, user):              │  │
│  │  1. Render HTML template: refund_request_email.html          │  │
│  │  2. Send to user.email (Customer)                            │  │
│  │  3. Render admin template: refund_request_admin_email.html   │  │
│  │  4. Send to DEFAULT_FROM_EMAIL (Admin)                       │  │
│  │  5. Both use SMTP configuration                              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ send_cancellation_request_email(order_product, user):        │  │
│  │  1. Render HTML template: cancellation_request_email.html    │  │
│  │  2. Send to user.email (Customer)                            │  │
│  │  3. Render admin template: cancellation_request_admin_email  │  │
│  │  4. Send to DEFAULT_FROM_EMAIL (Admin)                       │  │
│  │  5. Both use SMTP configuration                              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
                       JSON Response
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      DATABASE (SQLite3)                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  orders_orderproduct Table                                           │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ id | order_id | product_id | refund_status | cancellation_st│  │
│  │ ──────────────────────────────────────────────────────────  │  │
│  │ 42 | 5        | 12         | 'Requested'   | 'Active'       │  │
│  │ 43 | 5        | 15         | 'No Request'  | 'Cancelled'    │  │
│  │ 44 | 6        | 20         | 'Approved'    | 'Active'       │  │
│  │ ... | ...     | ...        | ...           | ...            │  │
│  │                                                               │  │
│  │ + refund_reason, cancellation_reason                         │  │
│  │ + refund_requested_at, cancellation_requested_at             │  │
│  │ + timestamps                                                 │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      ADMIN INTERFACE                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  OrderProduct Admin View                                             │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Order | Product | User | Qty | Price | Refund Status ↓ |   │  │
│  │ ────────────────────────────────────────────────────────── │  │
│  │ 5001  | Nike... | John  | 1   | 99.99 | Requested  │       │  │
│  │ 5001  | Adidas. | John  | 2   | 50.00 | No Request │       │  │
│  │ 5002  | Shoes.. | Jane  | 1   | 75.00 | Approved   │       │  │
│  │                                                               │  │
│  │ Filters: refund_status ▼ | cancellation_status ▼            │  │
│  │                                                               │  │
│  │ Actions: ▼ Select Action                                    │  │
│  │  ☐ Approve selected refund requests                         │  │
│  │  ☐ Reject selected refund requests                          │  │
│  │  ☐ Approve selected cancellation requests                   │  │
│  │  ☐ Go                                                       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  Detailed Edit View                                                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Basic Information                                             │  │
│  │  Order: [Order #5001]                                        │  │
│  │  Product: [Nike Shoes]                                       │  │
│  │  User: [john@example.com]                                    │  │
│  │                                                               │  │
│  │ ▶ Refund Information (Collapsed Section)                     │  │
│  │  refund_status: [ Requested ▼]                               │  │
│  │  refund_reason: "not as expected"                            │  │
│  │  refund_requested_at: 2026-01-28 12:30:45                    │  │
│  │                                                               │  │
│  │ ▶ Cancellation Information                                   │  │
│  │  cancellation_status: [Active]                               │  │
│  │  cancellation_reason: ""                                     │  │
│  │  cancellation_requested_at: (empty)                          │  │
│  │                                                               │  │
│  │ [Save] [Delete] [History] [Save and continue editing]        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
                      Admin Updates Status
                              ↓
                      Database Updated
```

---

## 📊 DATA FLOW DIAGRAM

```
┌──────────────┐
│  Customer    │
│ (Logged In)  │
└──────────────┘
       │
       │ 1. Navigates to Order Tracking
       ↓
┌──────────────────────────────────┐
│ Order Tracking Page              │
│ - Shows product items            │
│ - Shows Refund button (if okay)  │
│ - Shows Cancel button (if active)│
└──────────────────────────────────┘
       │
       │ 2. Clicks button
       ↓
┌──────────────────────────────────┐
│ Modal Dialog Opens               │
│ - Shows product name             │
│ - Asks for reason (optional)     │
│ - Confirm button                 │
└──────────────────────────────────┘
       │
       │ 3. Submits modal
       ↓
┌──────────────────────────────────┐
│ JavaScript Handler               │
│ - Collects data                  │
│ - Validates form                 │
│ - Sends AJAX POST                │
└──────────────────────────────────┘
       │
       │ 4. AJAX POST
       │    /orders/request_refund/
       │    {
       │      order_product_id: 42,
       │      reason: "..."
       │    }
       ↓
┌──────────────────────────────────┐
│ Django View (request_refund)     │
│ 1. Verify authentication         │
│ 2. Get OrderProduct              │
│ 3. Verify user ownership         │
│ 4. Check status                  │
│ 5. Update database               │
│ 6. Send emails                   │
│ 7. Return JSON                   │
└──────────────────────────────────┘
       │
       │ Updates OrderProduct
       ↓
┌──────────────────────────────────┐
│ Database Update                  │
│ refund_status='Requested'        │
│ refund_reason='...'              │
│ refund_requested_at=NOW()        │
└──────────────────────────────────┘
       │
       ├────────────────────────────┐
       │                            │
       │ Email 1                    │ Email 2
       ↓                            ↓
  ┌─────────────┐          ┌─────────────────┐
  │ Customer    │          │ Admin/Staff     │
  │ Email Box   │          │ Email Box       │
  │             │          │                 │
  │ "Refund     │          │ "[ADMIN]        │
  │ Request     │          │ Refund Request" │
  │ Received"   │          │                 │
  └─────────────┘          │ (Review link)   │
                           └─────────────────┘
                                  │
                                  │ 8. Admin Reviews
                                  ↓
                           ┌──────────────────┐
                           │ Admin Dashboard  │
                           │ Order Products   │
                           │ - Filter Request │
                           │ - Approve/Reject │
                           └──────────────────┘
                                  │
                                  │ Updates Status
                                  ↓
                           ┌──────────────────┐
                           │ Database Update  │
                           │ refund_status=   │
                           │ 'Approved'/      │
                           │ 'Rejected'       │
                           └──────────────────┘
       │
       │ 9. JavaScript Success Handler
       ↓
┌──────────────────────────────────┐
│ Frontend Updates                 │
│ - Hide button                    │
│ - Show success alert             │
│ - Show status badge              │
│ - Reload page (2 seconds)        │
└──────────────────────────────────┘
       │
       │ 10. Page Reloaded
       ↓
┌──────────────────────────────────┐
│ Order Tracking Page              │
│ - Same page, updated state       │
│ - Status shows: "Refund:         │
│                  Requested"      │
│ - Button hidden                  │
└──────────────────────────────────┘
```

---

## 🔄 STATE MACHINE DIAGRAM

### **Refund Status Machine**
```
┌─────────────┐
│ No Request  │  ← Initial State
└──────┬──────┘
       │ Customer clicks "Refund"
       ↓
┌─────────────────┐
│ Requested       │  ← Awaiting Admin Review
└──┬──────────────┘
   │
   ├─ Admin approves
   │  ↓
   │  ┌──────────┐
   │  │ Approved │  ← Refund will be processed
   │  └──────────┘
   │
   └─ Admin rejects
      ↓
      ┌──────────┐
      │ Rejected │  ← Refund denied
      └──────────┘
```

### **Cancellation Status Machine**
```
┌────────┐
│ Active │  ← Initial State
└───┬────┘
    │ Customer clicks "Cancel"
    ↓
┌─────────────────────────┐
│ Cancellation Requested  │  ← Awaiting Admin Review
└──────┬──────────────────┘
       │ Admin approves
       ↓
    ┌──────────┐
    │ Cancelled│  ← Product cancelled, refund pending
    └──────────┘
```

---

## 📧 EMAIL ROUTING

```
Request Submitted
       │
       ├─────────────────────────┐
       │                         │
       │                         │
       ↓                         ↓
┌──────────────┐        ┌──────────────────┐
│ Django View  │        │ Django View      │
│ gets user    │        │ builds admin     │
│ email addr   │        │ email addr from  │
│              │        │ settings         │
└────────┬─────┘        └────────┬─────────┘
         │                       │
         ↓                       ↓
  ┌────────────────┐    ┌──────────────────┐
  │ Render HTML    │    │ Render Admin     │
  │ Customer       │    │ Notification     │
  │ template       │    │ template         │
  └────────┬───────┘    └────────┬─────────┘
           │                     │
           ↓                     ↓
  ┌──────────────────┐  ┌──────────────────┐
  │ EmailMultiAltern│  │ EmailMultiAltern │
  │ -atives         │  │ -atives          │
  │ To: user.email  │  │ To: admin.email  │
  └────────┬────────┘  └────────┬─────────┘
           │                    │
           └────────┬───────────┘
                    │
                    ↓
          ┌──────────────────┐
          │ SMTP Server      │
          │ (Django Config)  │
          └──────────────────┘
                    │
          ┌─────────┴─────────┐
          │                   │
          ↓                   ↓
    ┌──────────┐        ┌──────────┐
    │ Customer │        │ Admin    │
    │ Mailbox  │        │ Mailbox  │
    └──────────┘        └──────────┘
```

---

## 🔒 SECURITY LAYERS

```
                  Request Received
                         │
                         ↓
         ┌───────────────────────────────────┐
         │ 1. CSRF Token Validation          │
         │    (Django middleware)            │
         └───────────────┬───────────────────┘
                         │
                         ↓
         ┌───────────────────────────────────┐
         │ 2. Authentication Check           │
         │    (@login_required)              │
         └───────────────┬───────────────────┘
                         │
                         ↓
         ┌───────────────────────────────────┐
         │ 3. User Ownership Verification    │
         │    (order_product.user ==         │
         │     request.user)                 │
         └───────────────┬───────────────────┘
                         │
                         ↓
         ┌───────────────────────────────────┐
         │ 4. Status State Validation        │
         │    (Check current status before   │
         │     allowing action)              │
         └───────────────┬───────────────────┘
                         │
                         ↓
         ┌───────────────────────────────────┐
         │ 5. Input Validation               │
         │    (Validate refund_status,       │
         │     reason, product_id)           │
         └───────────────┬───────────────────┘
                         │
                         ↓
         ┌───────────────────────────────────┐
         │ 6. Database Transaction           │
         │    (Save changes atomically)      │
         └───────────────┬───────────────────┘
                         │
                         ↓
         ┌───────────────────────────────────┐
         │ 7. Error Handling                 │
         │    (Try-except, graceful errors)  │
         └───────────────┬───────────────────┘
                         │
                         ↓
                   Secure Request
                   Processed ✅
```

---

## 🚀 REQUEST LIFECYCLE

```
TIME    CLIENT              NETWORK             SERVER              DATABASE        EMAIL
│                                                                                     │
├─ T0:  User clicks button                                                           │
│       ├─ Modal opens                                                               │
│       └─ Fills form                                                                │
│                                                                                     │
├─ T1:  Submits form                                                                 │
│       └─ AJAX POST ────────────────────→ Receives request                         │
│                                         └─ Parses JSON                             │
│                                         └─ Validates CSRF                          │
│                                         └─ Checks auth                             │
│                                                                                     │
├─ T2:                                    Gets OrderProduct ──────→ Queries DB       │
│                                         ├─ Validates ownership                     │
│                                         └─ Checks status                           │
│                                                                   ← Returns obj      │
│                                                                                     │
├─ T3:                                    Updates fields                             │
│                                         ├─ refund_status                           │
│                                         ├─ refund_reason                           │
│                                         └─ refund_requested_at                     │
│                                                 │                                   │
│                                                 └─ Saves ────────→ Updates row     │
│                                                                   ← Commit         │
│                                                                                     │
├─ T4:                                    Renders email templates                    │
│                                         ├─ Customer template                       │
│                                         ├─ Admin template                          │
│                                         └─ Sends via SMTP ─────────────────────→ SMTP
│                                                                                      │
├─ T5:                                    Returns JSON response                      │
│       ← JSON response ──────────────────
│       {'success': True,
│        'message': '...'}
│
├─ T6:  JavaScript handles response       
│       ├─ Close modal                    
│       ├─ Show alert                     
│       ├─ Wait 2 seconds                 
│       └─ Reload page                    
│                                                                                     │
├─ T7:  GET order tracking page ────────→ View renders page                         │
│                                         └─ Fetches updated data ──→ SQL query     │
│                                                                   ← Returns obj    │
│       ← New HTML ──────────────────────                                           │
│       ├─ Hidden refund button                                                     │
│       └─ Updated status badge                                                     │
│                                                                                     │
└─ T8:  Page displays                   (After ~2 seconds total)  ← Emails delivered
        with updated state
```

---

## 📈 TRAFFIC FLOW

```
Customer Tier:
    10 → 100 → 1000 requests/day
    └─ Refund requests
    └─ Cancellation requests

Admin Tier:
    1 → 10 → 100 requests/day
    └─ Approval actions
    └─ Rejection actions
    └─ Review requests

System Load:
    - View processing: ~50ms
    - Database operations: ~10ms
    - Email sending: ~500ms (async recommended for production)
    - Total per request: ~560ms (without async)
    - With async: ~50ms (email queued)
```

---

**End of Architecture Documentation**
