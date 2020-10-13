import chipwhisperer as cw

SCOPETYPE = 'OPENADC'
PLATFORM = 'CWLITEXMEGA'
CRYPTO_TARGET = 'AVRCRYPTOLIB'


from Setup_Generic import Setup

scope,prog,target = Setup(PLATFORM)

fw_path = '../simpleserial-aes-CWLITEXMEGA.AVRLIB.hex' #Firmware

cw.program_target(scope, prog, fw_path)

import chipwhisperer.analyzer as cwa
import matplotlib.pyplot as plt
import progressbar
from csv import writer

ktp = cw.ktp.Basic()
ktp.fixed_key = False

leak_model = cwa.leakage_models.sbox_output

num_traces = 10


def append_list_as_row(file, item):
    with open(file, 'a+', newline='')as write_obj:
        csv_writer = writer(write_obj)
        csv_writer.writerow(item)


for i in range(0,1):  # loop for each different key
    print("working on key", i, ":")
    key = ktp.next_key()  # Next Key
    proj = cw.create_project("../collections/May_18_RevisedFirmware/Key_{}.cwp".format(i), overwrite=True)

    # collection for each key
    for j in progressbar.progressbar(range(num_traces)):
        text = ktp.next_text()  # next textin
        trace = cw.capture_trace(scope, target, text, key)
        while (trace is None):
            trace = cw.capture_trace(scope, target, text, key)
        proj.traces.append(trace)
    proj.save()

    # Sample Trace Part
    plt.plot(proj.waves[0])
    plt.xlabel('Time')
    plt.ylabel('Amplitude')
    plt.show()
    #plt.savefig('../collections/May_18_RevisedFirmware/Key{}_wave0.png'.format(i))
    print("Key", i, "finished", "Imagin Saved")
    plt.clf()

    '''
    # convert to cvs
    for trace in proj.traces:
        append_list_as_row('../collections/May_18_RevisedFirmware/key{}_trace.csv'.format(i), trace.wave)
        append_list_as_row('../collections/May_18_RevisedFirmware/key{}_key.csv'.format(i), trace.key)
        append_list_as_row('../collections/May_18_RevisedFirmware/key{}_textin.csv'.format(i), trace.textin)
        append_list_as_row('../collections/May_18_RevisedFirmware/key{}_textout.csv'.format(i), trace.textout)
    '''
#Doing attack using CPA
results = []
for i in range(0, 32):
    proj = cw.open_project("../collections/May_18_RevisedFirmware/Key_{}.cwp".format(i))

    # Attack part, makesure each key is woring fine
    attack = cwa.cpa(proj, leak_model)
    result = attack.run()
    print("Attack finshed, for Key", i, "result is:")
    print(result)
    results.append(result)
    try:
        assert (result.find_key() == proj.keys[0])
    except:
        print("result", i, "is wrong:")
        print("except:", proj.keys[0])
        print("result:", result.find_key())


