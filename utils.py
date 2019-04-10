from datetime import datetime


def reporttitle(text):
    line = "{}\n".format("#" * 80)
    now = str(datetime.now())[:19]
    output = "\n{0}#{1:^78}#\n#{2:^78}#\n{0}".format(line, text, now)
    return output


def detailchapter(text):
    line = "{}\n".format("*" * 80)
    output = "\n{0}**{1:^76}**\n{0}".format(line, text)
    return output


def detailheader(text):
    line = "\n{}\n".format("=" * 80)
    output = "{0}||{1:^76}||{0}".format(line, text)
    return output


def detailfile(text):
    line = "\n{}\n".format("-" * 80)
    output = "\n{1:^80}{0}".format(line, text)
    return output


def converthex2ip(hextext):
    hextext = "{}.{}.{}.{}".format(int(hextext[6:8], 16), int(hextext[4:6], 16),
                                   int(hextext[2:4], 16), int(hextext[0:2], 16))
    return hextext


def converthex2ipport(hextext):
    ip = "{}.{}.{}.{}".format(int(hextext[6:8], 16), int(hextext[4:6], 16),
                              int(hextext[2:4], 16), int(hextext[0:2], 16))
    port = "{}".format(int(hextext[9:], 16))

    return ip, port

def percentagebar(total, step):
    if total > 0:
        percentage = int(100 * step / total)
    else:
        percentage = 100
    before = "[{}".format("=" * (percentage * 0.75))
    after = "{}]".format(" " * (100 - (percentage * 0.75)))
    print("\r{}{:02}%{}".format(before, percentage, after), end="")
