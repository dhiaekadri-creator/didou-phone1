const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const db = new Database(process.env.DB_FILE || 'didou-phone.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT DEFAULT '', wilaya TEXT DEFAULT '', address TEXT DEFAULT '', password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, brand TEXT NOT NULL, price INTEGER NOT NULL,
 old_price INTEGER DEFAULT NULL, storage TEXT DEFAULT '', ram TEXT DEFAULT '', color TEXT DEFAULT '',
 image TEXT DEFAULT '', stock INTEGER NOT NULL DEFAULT 0, featured INTEGER NOT NULL DEFAULT 0,
 description TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER DEFAULT NULL, customer_name TEXT NOT NULL, phone TEXT NOT NULL,
 wilaya TEXT NOT NULL, address TEXT NOT NULL, notes TEXT DEFAULT '', items_json TEXT NOT NULL,
 total INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'New', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);
try { db.exec('ALTER TABLE orders ADD COLUMN user_id INTEGER DEFAULT NULL'); } catch (e) { if (!String(e.message).includes('duplicate column')) throw e; }
const count = db.prepare('SELECT COUNT(*) AS n FROM products').get().n;
if (!count) {
 const add = db.prepare(`INSERT INTO products(name,brand,price,old_price,storage,ram,color,image,stock,featured,description)
 VALUES(?,?,?,?,?,?,?,?,?,?,?)`);
 [
  ['iPhone 15','Apple',149900,159900,'128 GB','6 GB','Black','',8,1,'Apple iPhone 15 — excellent condition and premium performance.'],
  ['Galaxy S24','Samsung',169900,179900,'256 GB','8 GB','Gray','',6,1,'Samsung Galaxy S24 with vivid display and powerful camera.'],
  ['Redmi Note 13','Xiaomi',48900,null,'256 GB','8 GB','Blue','',14,1,'Great value smartphone for everyday use.'],
  ['realme C67','realme',39900,null,'128 GB','8 GB','Green','',10,0,'Reliable everyday smartphone with a stylish design.'],
  ['iPhone 13','Apple',109900,null,'128 GB','4 GB','Midnight','',5,0,'A popular iPhone with smooth performance.'],
  ['Galaxy A35','Samsung',79900,null,'128 GB','8 GB','Navy','',7,0,'Balanced Samsung smartphone for work and entertainment.']
 ].forEach(p=>add.run(...p));
}
const adminName = process.env.ADMIN_USERNAME;
const adminPass = process.env.ADMIN_PASSWORD;
if (adminName && adminPass && adminPass.length >= 12 && !db.prepare('SELECT id FROM admins WHERE username=?').get(adminName)) {
 db.prepare('INSERT INTO admins(username,password_hash) VALUES(?,?)').run(adminName,bcrypt.hashSync(adminPass,12));
}
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{
 defaultSrc:["'self'"], scriptSrc:["'self'"], styleSrc:["'self'","'unsafe-inline'"],
 imgSrc:["'self'","data:","https:"], connectSrc:["'self'"], objectSrc:["'none'"], upgradeInsecureRequests:null
}}}));
app.use(express.json({limit:'200kb'}));
app.use(express.urlencoded({extended:false,limit:'20kb'}));
app.use(session({
 name:'didou.sid', secret:process.env.SESSION_SECRET || 'development-only-change-this-secret',
 resave:false, saveUninitialized:false, store:new SQLiteStore({db:'sessions.sqlite',dir:'.'}),
 cookie:{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000}
}));
const loginLimiter=rateLimit({windowMs:15*60*1000,max:8,standardHeaders:true,legacyHeaders:false});
const auth=(req,res,next)=>req.session.admin?next():res.status(401).json({error:'Please sign in as admin.'});
const userAuth=(req,res,next)=>req.session.user?next():res.status(401).json({error:'Please sign in to your customer account.'});
const safeProduct=p=>({...p,featured:!!p.featured});
app.get('/api/config',(req,res)=>res.json({phone:process.env.STORE_PHONE||'',wilaya:process.env.STORE_WILAYA||'Algeria'}));
app.get('/api/products',(req,res)=>{
 const {q='',brand=''}=req.query;
 let sql='SELECT * FROM products WHERE stock > 0',args=[];
 if(q){sql+=' AND (name LIKE ? OR brand LIKE ?)';args.push('%'+q+'%','%'+q+'%');}
 if(brand){sql+=' AND brand=?';args.push(brand);}
 sql+=' ORDER BY featured DESC, id DESC';
 res.json(db.prepare(sql).all(...args).map(safeProduct));
});
const userLoginLimiter=rateLimit({windowMs:15*60*1000,max:10,standardHeaders:true,legacyHeaders:false});
app.post('/api/account/register',userLoginLimiter,(req,res)=>{
 const {full_name,email,password,phone='',wilaya='',address=''}=req.body||{};
 const name=String(full_name||'').trim(),mail=String(email||'').trim().toLowerCase(),pass=String(password||'');
 if(name.length<2||name.length>100||!/^\S+@\S+\.\S+$/.test(mail)||pass.length<10||pass.length>100)
  return res.status(400).json({error:'Enter your name, a valid email, and a password of at least 10 characters.'});
 try{const r=db.prepare('INSERT INTO users(full_name,email,phone,wilaya,address,password_hash) VALUES(?,?,?,?,?,?)').run(name,mail,String(phone).slice(0,30),String(wilaya).slice(0,100),String(address).slice(0,300),bcrypt.hashSync(pass,12));
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not create session.'});req.session.user={id:r.lastInsertRowid,email:mail};res.status(201).json({ok:true});});
 }catch(e){if(String(e.message).includes('UNIQUE'))return res.status(409).json({error:'An account with this email already exists.'});res.status(500).json({error:'Could not create account.'});}
});
app.post('/api/account/login',userLoginLimiter,(req,res)=>{
 const email=String(req.body?.email||'').trim().toLowerCase(),password=String(req.body?.password||'');
 const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:'Email or password is incorrect.'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Sign in failed.'});req.session.user={id:u.id,email:u.email};res.json({ok:true});});
});
app.get('/api/account/me',userAuth,(req,res)=>{const u=db.prepare('SELECT id,full_name,email,phone,wilaya,address,created_at FROM users WHERE id=?').get(req.session.user.id);if(!u)return res.status(401).json({error:'Account not found.'});res.json(u);});
app.put('/api/account/me',userAuth,(req,res)=>{const {full_name,phone='',wilaya='',address=''}=req.body||{};if(String(full_name||'').trim().length<2||String(full_name).length>100||String(phone).length>30||String(wilaya).length>100||String(address).length>300)return res.status(400).json({error:'Please check your profile details.'});db.prepare('UPDATE users SET full_name=?,phone=?,wilaya=?,address=? WHERE id=?').run(String(full_name).trim(),String(phone).trim(),String(wilaya).trim(),String(address).trim(),req.session.user.id);res.json({ok:true});});
app.post('/api/account/change-password',userAuth,(req,res)=>{const oldp=String(req.body?.current_password||''),newp=String(req.body?.new_password||'');const u=db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.session.user.id);if(!u||!bcrypt.compareSync(oldp,u.password_hash))return res.status(400).json({error:'Current password is incorrect.'});if(newp.length<10||newp.length>100)return res.status(400).json({error:'New password must be at least 10 characters.'});db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(newp,12),req.session.user.id);res.json({ok:true});});
app.get('/api/account/orders',userAuth,(req,res)=>res.json(db.prepare('SELECT id,items_json,total,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC').all(req.session.user.id).map(o=>({...o,items:JSON.parse(o.items_json)}))));
app.post('/api/account/logout',userAuth,(req,res)=>{delete req.session.user;req.session.save(()=>res.json({ok:true}));});
app.post('/api/orders',(req,res)=>{
 const {customer_name,phone,wilaya,address,notes='',items}=req.body||{};
 if(!customer_name||!phone||!wilaya||!address||!Array.isArray(items)||!items.length||items.length>20)
  return res.status(400).json({error:'Please complete the required order details.'});
 if(String(customer_name).length>100||String(phone).length>30||String(address).length>300||String(notes).length>500)
  return res.status(400).json({error:'Some fields are too long.'});
 const validPhone=String(phone).replace(/[^\d+]/g,'');
 if(validPhone.length<8||validPhone.length>18)return res.status(400).json({error:'Please enter a valid phone number.'});
 const transaction=db.transaction(()=>{
  let total=0,confirmed=[];
  for(const item of items){
   const id=Number(item.id),qty=Number(item.quantity);
   if(!Number.isInteger(id)||!Number.isInteger(qty)||qty<1||qty>10)throw new Error('Invalid product or quantity.');
   const p=db.prepare('SELECT id,name,price,stock FROM products WHERE id=?').get(id);
   if(!p||p.stock<qty)throw new Error('A product is unavailable or has insufficient stock.');
   total+=p.price*qty;confirmed.push({id:p.id,name:p.name,price:p.price,quantity:qty});
  }
  const ins=db.prepare(`INSERT INTO orders(user_id,customer_name,phone,wilaya,address,notes,items_json,total)
   VALUES(?,?,?,?,?,?,?,?)`).run(req.session.user?.id||null,String(customer_name).trim(),validPhone,String(wilaya).trim(),String(address).trim(),String(notes).trim(),JSON.stringify(confirmed),total);
  for(const item of confirmed)db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(item.quantity,item.id);
  return ins.lastInsertRowid;
 });
 try{const id=transaction();res.status(201).json({ok:true,order_id:id,message:'Order received. We will contact you to confirm.'});}
 catch(e){res.status(400).json({error:e.message||'Could not place order.'});}
});
app.post('/api/admin/login',loginLimiter, (req,res)=>{
 const {username,password}=req.body||{};
 const admin=db.prepare('SELECT * FROM admins WHERE username=?').get(String(username||''));
 if(!admin||!bcrypt.compareSync(String(password||''),admin.password_hash))return res.status(401).json({error:'Incorrect username or password.'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Login failed.'});req.session.admin={id:admin.id,username:admin.username};res.json({ok:true});});
});
app.get('/api/admin/me',auth,(req,res)=>res.json({username:req.session.admin.username}));
app.post('/api/admin/logout',auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/summary',auth,(req,res)=>{
 const products=db.prepare('SELECT COUNT(*) n FROM products').get().n;
 const orders=db.prepare('SELECT COUNT(*) n FROM orders').get().n;
 const revenue=db.prepare("SELECT COALESCE(SUM(total),0) n FROM orders WHERE status='Delivered'").get().n;
 const pending=db.prepare("SELECT COUNT(*) n FROM orders WHERE status IN ('New','Confirmed')").get().n;
 res.json({products,orders,revenue,pending});
});
app.get('/api/admin/customers',auth,(req,res)=>res.json(db.prepare('SELECT id,full_name,email,phone,wilaya,address,created_at FROM users ORDER BY id DESC').all()));
app.get('/api/admin/products',auth,(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.post('/api/admin/products',auth,(req,res)=>{
 const p=req.body||{};
 if(!p.name||!p.brand||!Number.isInteger(Number(p.price))||Number(p.price)<0||!Number.isInteger(Number(p.stock))||Number(p.stock)<0)
  return res.status(400).json({error:'Name, brand, valid price and stock are required.'});
 const r=db.prepare(`INSERT INTO products(name,brand,price,old_price,storage,ram,color,image,stock,featured,description)
 VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(p.name,p.brand,Number(p.price),p.old_price?Number(p.old_price):null,p.storage||'',p.ram||'',p.color||'',p.image||'',Number(p.stock),p.featured?1:0,p.description||'');
 res.status(201).json({id:r.lastInsertRowid});
});
app.put('/api/admin/products/:id',auth,(req,res)=>{
 const p=req.body||{};
 if(!p.name||!p.brand||!Number.isInteger(Number(p.price))||Number(p.price)<0||!Number.isInteger(Number(p.stock))||Number(p.stock)<0)
  return res.status(400).json({error:'Name, brand, valid price and stock are required.'});
 const r=db.prepare(`UPDATE products SET name=?,brand=?,price=?,old_price=?,storage=?,ram=?,color=?,image=?,stock=?,featured=?,description=? WHERE id=?`)
 .run(p.name,p.brand,Number(p.price),p.old_price?Number(p.old_price):null,p.storage||'',p.ram||'',p.color||'',p.image||'',Number(p.stock),p.featured?1:0,p.description||'',Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:'Product not found.'});res.json({ok:true});
});
app.delete('/api/admin/products/:id',auth,(req,res)=>{db.prepare('DELETE FROM products WHERE id=?').run(Number(req.params.id));res.json({ok:true});});
app.get('/api/admin/orders',auth,(req,res)=>res.json(db.prepare('SELECT * FROM orders ORDER BY id DESC').all().map(o=>({...o,items:JSON.parse(o.items_json)}))));
app.patch('/api/admin/orders/:id',auth,(req,res)=>{
 const statuses=['New','Confirmed','Preparing','Shipped','Delivered','Cancelled'];
 if(!statuses.includes(req.body.status))return res.status(400).json({error:'Invalid order status.'});
 const r=db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status,Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:'Order not found.'});res.json({ok:true});
});
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`DIDOU PHONE running on http://localhost:${port}`));