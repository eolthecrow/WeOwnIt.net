from pathlib import Path
import json
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.utils import simpleSplit

REPO=Path(__file__).resolve().parents[1]
OUT=REPO/'downloads'; OUT.mkdir(exist_ok=True)
W,H=A4
C={k:colors.HexColor(v) for k,v in {'bg':'#0a151c','panel':'#102029','panel2':'#12232b','ink':'#f2f1e8','muted':'#a6b8ba','quiet':'#81969a','accent':'#6ce2c7','amber':'#f4bc79','red':'#f29a8b','line':'#29404a'}.items()}
pdfmetrics.registerFont(TTFont('DV','/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
pdfmetrics.registerFont(TTFont('DVB','/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'))

def wrap(c,text,x,y,w,size=8.4,color=None,bold=False,lead=None,max_lines=12):
    font='DVB' if bold else 'DV'; color=color or C['muted']; lead=lead or size*1.35
    c.setFont(font,size); c.setFillColor(color)
    for line in simpleSplit(text,font,size,w)[:max_lines]: c.drawString(x,y,line); y-=lead
    return y

def head(c,d,n,title=''):
    c.setFillColor(C['bg']); c.rect(0,0,W,H,fill=1,stroke=0)
    c.setFillColor(C['accent']); c.rect(34,H-48,22,2,fill=1,stroke=0)
    c.setFont('DVB',8); c.setFillColor(C['muted']); c.drawString(62,H-51,'WEOWNIT.NET / NETWORK & SECURITY')
    c.setFont('DV',7); c.setFillColor(C['quiet']); c.drawRightString(W-34,H-51,f"{d['lang']}  ·  SAMPLE  ·  {n:02d}/10")
    if title:
        c.setFont('DVB',20); c.setFillColor(C['ink']); c.drawString(34,H-84,title)

def foot(c,d):
    c.setStrokeColor(C['line']); c.line(34,28,W-34,28)
    c.setFont('DV',6.1); c.setFillColor(C['quiet']); c.drawString(34,17,d['footer'][:115]); c.drawRightString(W-34,17,'weownit.net')

def card(c,x,y,w,h,label,body,hi=False):
    c.setFillColor(C['panel2'] if hi else C['panel']); c.setStrokeColor(C['accent'] if hi else C['line']); c.roundRect(x,y-h,w,h,5,fill=1,stroke=1)
    c.setFont('DVB',7.7); c.setFillColor(C['accent'] if hi else C['amber']); c.drawString(x+11,y-17,label.upper())
    wrap(c,body,x+11,y-34,w-22,8.2,C['muted'],False,10.8,11)

def architecture(c):
    y=H-160
    pts=[('INTERNET',34,y),('EDGE FIREWALL',212,y),('USER',34,y-88),('SERVER',178,y-88),('MGMT',322,y-88),('BRANCH VPN',432,y-88)]
    for label,x,yy in pts:
        c.setFillColor(C['panel2']); c.setStrokeColor(C['accent'] if label in ('EDGE FIREWALL','MGMT') else C['line']); c.roundRect(x,yy,110,40,5,fill=1,stroke=1)
        c.setFont('DVB',7.2); c.setFillColor(C['ink']); c.drawCentredString(x+55,yy+16,label)
    c.setStrokeColor(C['muted']); c.line(144,y+20,212,y+20); c.line(267,y,267,y-30)
    for x in (89,233,377,487): c.line(267,y-30,x,y-30); c.line(x,y-30,x,y-48)
    c.setStrokeColor(C['red']); c.setLineWidth(2); c.line(89,y-48,377,y-48)
    c.setFont('DVB',7); c.setFillColor(C['red']); c.drawString(120,y-42,'UNNECESSARY ADMIN PATH')

def matrix(c):
    x=330; y=H-176; cell=32
    for r in range(5):
        for q in range(5):
            score=(r+1)*(q+1); fill='#18302e' if score<8 else ('#4b3b25' if score<15 else '#4b2928')
            c.setFillColor(colors.HexColor(fill)); c.setStrokeColor(C['line']); c.rect(x+q*cell,y-(r+1)*cell,cell,cell,fill=1,stroke=1)
            c.setFillColor(C['ink']); c.setFont('DVB',7); c.drawCentredString(x+q*cell+16,y-(r+1)*cell+12,str(score))
    c.setFillColor(C['red']); c.circle(x+4*cell+16,y-4*cell+16,5,fill=1,stroke=0)

def page(c,d,n,p):
    head(c,d,n,p['title']); c.setFont('DV',8.3); c.setFillColor(C['muted']); c.drawString(34,H-104,p['subtitle'])
    top=H-128
    if p.get('diagram')=='architecture': architecture(c); top=H-310
    if p.get('diagram')=='matrix': matrix(c)
    if p.get('attack'):
        c.setFillColor(C['panel']); c.setStrokeColor(C['line']); c.roundRect(34,H-180,W-68,38,5,fill=1,stroke=1)
        c.setFont('DVB',7.4); c.setFillColor(C['accent']); c.drawString(45,H-158,'ATTACK PATH')
        c.setFont('DV',7.4); c.setFillColor(C['ink']); c.drawString(124,H-158,'Compromised endpoint  ->  User zone  ->  Firewall management  ->  Privileged control'); top=H-198
    items=p['items']
    if p.get('diagram')=='matrix':
        y=H-148
        for i,it in enumerate(items): card(c,34,y,260,60,it[0],it[1],i==0); y-=69
    elif len(items)>=5:
        col=(W-78)/2; ys=[top,top]
        for i,it in enumerate(items):
            k=i%2; h=88 if len(it[1])>145 else 72; card(c,34+k*(col+10),ys[k],col,h,it[0],it[1],i==0); ys[k]-=h+10
    else:
        y=top
        for i,it in enumerate(items):
            h=92 if len(it[1])>175 else 76; card(c,34,y,W-68,h,it[0],it[1],i==0); y-=h+11
    foot(c,d); c.showPage()

def build(locale):
    d=json.loads((REPO/'tools'/f'free_sample_{locale}.json').read_text(encoding='utf-8'))
    path=OUT/f'WeOwnIT_Network_Security_Assessment_Sample_{locale.upper()}_2026.pdf'; c=canvas.Canvas(str(path),pagesize=A4)
    head(c,d,1); c.setFont('DVB',8); c.setFillColor(C['accent']); c.drawString(34,H-126,d['badge'])
    size=24 if locale=='ro' else 27; c.setFont('DVB',size); c.setFillColor(C['ink'])
    y=H-184
    for line in simpleSplit(d['cover'],'DVB',size,W-68): c.drawString(34,y,line); y-=size*1.15
    c.setFont('DV',15); c.setFillColor(C['muted']); c.drawString(34,y-8,d['sub'])
    c.setFillColor(C['panel2']); c.roundRect(34,H-390,W-68,104,7,fill=1,stroke=0)
    c.setFont('DVB',10); c.setFillColor(C['accent']); c.drawString(50,H-315,'ASSESS  ->  FIX  ->  VALIDATE  ->  PROVE')
    wrap(c,d['footer'],50,H-342,W-100,8.7,C['muted'],False,12,5)
    c.setFont('DVB',10); c.setFillColor(C['ink']); c.drawString(34,90,'WeOwnIT / Network & Security Consulting')
    c.setFont('DV',7.6); c.setFillColor(C['quiet']); c.drawString(34,71,'Risk-informed security engineering · Architecture · Remediation · Validation')
    foot(c,d); c.showPage()
    for n,p in enumerate(d['pages'],2): page(c,d,n,p)
    c.save(); print(path)

for loc in ('en','ro','fr'): build(loc)
