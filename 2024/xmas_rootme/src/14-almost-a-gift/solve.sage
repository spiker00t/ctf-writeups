from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long,long_to_bytes

def SDA_solver(xs, rho):
    """
    Basic idea: xi / x0 = qi / q0
    Construct lattice to attack.
    B = [2^(rho+1)  x1   x2  ....  xt]
        [           -x0              ]
        [                -x0         ]
        [                   .        ]
        [                     .      ]
        [                       .    ]
        [                         -x0]
    v = (q0, q1, ..., qt)B
      = (q0*2^(rho+1), q0r1-q1r0, ..., q0rt-qtr0)
    B.LLL() to solve for q0 so we can solve for p
    """

    # 1. Construct lattice
    t = len(xs) - 1
    B = Matrix(ZZ, t+1, t+1)
    for i in range(t+1):
        B[i, i] = -xs[0]
        if i == 0:
            B[0, i] = 2^(rho+1)
        else:
            B[0, i] = xs[i]
    # 2. LLL and find p
    v = B.LLL()[0]
    q0 = v[0] // 2^(rho+1)
    p = xs[0] // q0
    return p

gift = [6613665867955032404899707979909510894042408884604988452440575060729723301371839449835153253002870531050942319014253164972869348379611868050909639899197433337437764651168254517943007238896137478507873817695215428701014044024620941449489482505214336619312368103487402839071068892968655405305232012199632032468279615815978135395525055989085074102315629740846430709809757228486254215749889741570126507465569688448790713948067554754014292061268408403713227743309402845417685208456366849822025070314152385682758915282484710719467818354668100703393638457894726693854623323613944050018626158651947626320599002341918396236718965591034738078341626133562537579382634125513406861981668252349279267016187576085171465902611337751406937378791956417607585784569307491002277608422156436821832537087730841575313647448409339, 6874268229023051307975802283502259992861678707188656773334363303226331663388739045744114816614966149291896253703504686452656527218852262007172232136206070977762750944621127995480056542618125312821568233289557798526442068479801372558087218242405070150852619958381584558012334339688028570201619358328506636125321405259048222216734946362623304755473264815742526495357663362901866996664643227341348383564682785414392672582065312051244229644201312345545650084404394586425215118660261339884969375584744687751287194335259981509512620902254159635213257429166913178554147004870666385014159060714916974118743966623730348183365506285526363855635369789659855883462772309522380916399885553041907982716517446140650392307277867915208131994038449888185979649054635644341972328303152956653072145512593531663306843896284421, 7111489028756353620391390609909219098944613129401314845663928958320068857083904896690481938162962720488257803571264212263132106504772017806923322671568170763334209201075404969970328495397507292142754953839163821230656383597975216248345192061837495103153710251361621873664408182279015636301067639875216385899498667515525830388770894770238161401274428156646827426792192651261523482535580946011925224081809663418731410822984342293970270818128153337700963061161368854511724136784768754329343698253876034784188893143469709712725817896902123541275543212251112640660498326988996732199511903848464212347091352152371770968605108047331694232352611233812071085109249036628717936593772545892941564930165030510737616020390300278273200517531800067203731765473521447067889244102437327376095629970569934157625353957958901, 7727276005216826080481486422463007071911370761959369169673119749390867785784975769918752003726909303013410177631956991300908971669801036085779579702803222801629706230902346289282099405483888478351989127793482234486523727573641108608791571996051719614209106765068672397641220049467982178800646984135594652097103447511746172628964493183145358698225067042683666310987472931454442404041534890145345857917726626224388600453066944684422450696096166215148318645951642669415516655200319205890822668235326137599628946600230176779226789406173428927867115524686553035943878869698804303033995261984531344319279391825178353516579628317437284493595886992393041204707735719599152616170193025163797148083322178157378113795221013334345474481952576368663792869721857847431820746057613293045381735629190814610485475671133729]
n = 6058002433377237175068217077426535724891453464111603075403293630513795653055658763081394292029861292261036161105612308729379756128113927555906468462843050114202726411029199727655727516406314378384369292469302461605251840194177339654970163967747249428772968418606347440111143328799775693337545346837128763776996505042111351399537213169798897350062428629635965937893396465340117203083891654823911633111741384358564724237778100161010230775764765675075826402313019263809304876499530039787707572804196563822974190096589133134365993721621677166234216770872414972756044606107182442835994406135657743948523304381270299637157188052383195446064003754170183938693519628436332055771555355709568098410018460250346578088871469429215921496902136560892284294459807884849488130599501627416606045400033877118463419197613611
c = 3512674359544605871207130097557082814974902762169498487487322256364598276561900049229971038007153985829019404470361533215233739443880576658470868314306809010162357662110108297094036443667370385318202403633866065206074847075127124006912804630608516353370909028549011871739517466775636523953128454062155024372945890574976513231915149338257116031774152271311530630120301455549375045164105223728740580748873500752525490742893781357120065694721195565458894348208627356060539234230854072842354244311580651233596090474472391674141853600482245646679035071537628914157369584027134660062512709099533330945545451729262720225486974310002956650013597406162539189447190802161559384387132992855056453355404414438154181478447205096527266366400228357348687969465114623813981824247124279620301909880358940152609307698778673

R = SDA_solver(gift,666)

#R = 2857361463786981263927025746238688770373438465952935948938300572099253156985734231106772981220552239989743635210453880885143475896530605814717502601118129671502740996275773729006972277498352029438873831827713002930412281714063567071904795103069682874484466117962897540185710607357855763419686437725678803121003877192429308721532440759945472170228437085056758897152197990386192808571631998281916141819353

e = n // R

assert (R*e == n)

phi = (e-1) * (R-1)
d = pow(2 ** 16 + 1, -1, phi)

m = bytes(PKCS1_OAEP.new(RSA.construct((int(n), int(2 ** 16 + 1), int(d)))).decrypt(long_to_bytes(c)))

print("FLAG: %s" % m.decode())