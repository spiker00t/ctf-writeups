

# This file was *autogenerated* from the file solve.sage
from sage.all_cmdline import *   # import sage library

_sage_const_22565061734039416113482972045260378850335551437603658289704615027418557202724145368752149375889961980363950180328323175210320614855936633182393255865179856287531160520701504181536636178888957690581313854928560767072864352042737573507134186874192330515294832153222689620292170062536844410158394875422189502091059641377172877646733866246591028663640957757623024460547759402035334150076953624006427372367403531317508296240139348595881946971512709010668970161839227064298658561166783993816926121542224966430871213596301099976336198714307311340588307183266135926332579316881966662145397817192575093538782843784869276100533 = Integer(22565061734039416113482972045260378850335551437603658289704615027418557202724145368752149375889961980363950180328323175210320614855936633182393255865179856287531160520701504181536636178888957690581313854928560767072864352042737573507134186874192330515294832153222689620292170062536844410158394875422189502091059641377172877646733866246591028663640957757623024460547759402035334150076953624006427372367403531317508296240139348595881946971512709010668970161839227064298658561166783993816926121542224966430871213596301099976336198714307311340588307183266135926332579316881966662145397817192575093538782843784869276100533); _sage_const_7090676761511038537715990241548422453589203615488971276028090010135172374067879024595027390319557301451711645742582972722821701885251846126401984831564226357658717867308193240479414897592113603389326639780104216744439110171644024870374198268635821406653829289038223890558052776266036276837616987636724890369390862354786266974335834195770641383651623579785433573634779559259801143085171276694299511739790904917106980811500310945911314872523635880520036346563681629465732398370718884575152165241470126313266744867672885335455602309001507861735607115050144930850784907731581914537046453363905996837218231392462387930807 = Integer(7090676761511038537715990241548422453589203615488971276028090010135172374067879024595027390319557301451711645742582972722821701885251846126401984831564226357658717867308193240479414897592113603389326639780104216744439110171644024870374198268635821406653829289038223890558052776266036276837616987636724890369390862354786266974335834195770641383651623579785433573634779559259801143085171276694299511739790904917106980811500310945911314872523635880520036346563681629465732398370718884575152165241470126313266744867672885335455602309001507861735607115050144930850784907731581914537046453363905996837218231392462387930807); _sage_const_4807856659746554540384761225066384015772406312309222087365335807512750906135069862937039445867248288889534863419734669057747347873310770686781920717735265966670386330747307885825069770587158745071342289187203571110391360979885681860651287497925857531184647628597729278701941784086778427361417975825146507365759546940436668188428639773713612411058202635094262874088878972789112883390157572057747869114692970492381330563011664859153989944153981298671522781443901759988719136517303438758819537082141804649484207969208736143196893611193421172099870279407909171591480711301772653211746249092574185769806854290727386897332 = Integer(4807856659746554540384761225066384015772406312309222087365335807512750906135069862937039445867248288889534863419734669057747347873310770686781920717735265966670386330747307885825069770587158745071342289187203571110391360979885681860651287497925857531184647628597729278701941784086778427361417975825146507365759546940436668188428639773713612411058202635094262874088878972789112883390157572057747869114692970492381330563011664859153989944153981298671522781443901759988719136517303438758819537082141804649484207969208736143196893611193421172099870279407909171591480711301772653211746249092574185769806854290727386897332); _sage_const_21347444708084802799009803643009154957516780623513439256397111284232540925976405404037717619209767862025457480966156406137212998283220183850004479260766295026179409197591604629092400433020507437961259179520449648954561486537590101708148916291332356063463410603926027330689376982238081346262884223521443089140193435193866121534545452893346753443625552713799639857846515709632076996793452083702019956813802268746647146317605419578838908535661351996182059305808616421037741561956252825591468392522918218655115102457839934797969736587813630818348913788139083225532326860894187123104070953292506518972382789549134889771498 = Integer(21347444708084802799009803643009154957516780623513439256397111284232540925976405404037717619209767862025457480966156406137212998283220183850004479260766295026179409197591604629092400433020507437961259179520449648954561486537590101708148916291332356063463410603926027330689376982238081346262884223521443089140193435193866121534545452893346753443625552713799639857846515709632076996793452083702019956813802268746647146317605419578838908535661351996182059305808616421037741561956252825591468392522918218655115102457839934797969736587813630818348913788139083225532326860894187123104070953292506518972382789549134889771498); _sage_const_2024 = Integer(2024); _sage_const_2512 = Integer(2512); _sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_16 = Integer(16)
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long,long_to_bytes

rebel = _sage_const_22565061734039416113482972045260378850335551437603658289704615027418557202724145368752149375889961980363950180328323175210320614855936633182393255865179856287531160520701504181536636178888957690581313854928560767072864352042737573507134186874192330515294832153222689620292170062536844410158394875422189502091059641377172877646733866246591028663640957757623024460547759402035334150076953624006427372367403531317508296240139348595881946971512709010668970161839227064298658561166783993816926121542224966430871213596301099976336198714307311340588307183266135926332579316881966662145397817192575093538782843784869276100533 
santa = _sage_const_7090676761511038537715990241548422453589203615488971276028090010135172374067879024595027390319557301451711645742582972722821701885251846126401984831564226357658717867308193240479414897592113603389326639780104216744439110171644024870374198268635821406653829289038223890558052776266036276837616987636724890369390862354786266974335834195770641383651623579785433573634779559259801143085171276694299511739790904917106980811500310945911314872523635880520036346563681629465732398370718884575152165241470126313266744867672885335455602309001507861735607115050144930850784907731581914537046453363905996837218231392462387930807 
alliance = _sage_const_4807856659746554540384761225066384015772406312309222087365335807512750906135069862937039445867248288889534863419734669057747347873310770686781920717735265966670386330747307885825069770587158745071342289187203571110391360979885681860651287497925857531184647628597729278701941784086778427361417975825146507365759546940436668188428639773713612411058202635094262874088878972789112883390157572057747869114692970492381330563011664859153989944153981298671522781443901759988719136517303438758819537082141804649484207969208736143196893611193421172099870279407909171591480711301772653211746249092574185769806854290727386897332 
grinch = _sage_const_21347444708084802799009803643009154957516780623513439256397111284232540925976405404037717619209767862025457480966156406137212998283220183850004479260766295026179409197591604629092400433020507437961259179520449648954561486537590101708148916291332356063463410603926027330689376982238081346262884223521443089140193435193866121534545452893346753443625552713799639857846515709632076996793452083702019956813802268746647146317605419578838908535661351996182059305808616421037741561956252825591468392522918218655115102457839934797969736587813630818348913788139083225532326860894187123104070953292506518972382789549134889771498 

q = gcd(pow(alliance-_sage_const_2024 , _sage_const_2512 , rebel) - santa, rebel)

p = rebel // q

assert (p*q == rebel)

phi = (p-_sage_const_1 ) * (q-_sage_const_1 )
d = pow(_sage_const_2  ** _sage_const_16  + _sage_const_1 , -_sage_const_1 , phi)

m = bytes(PKCS1_OAEP.new(RSA.construct((int(rebel), int(_sage_const_2  ** _sage_const_16  + _sage_const_1 ), int(d)))).decrypt(long_to_bytes(grinch)))

print("FLAG: %s" % m.decode())
