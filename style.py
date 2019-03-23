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
