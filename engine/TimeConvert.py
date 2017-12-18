def timeConvert(x):
    # x is time in millisecond
    # return string: 'hour:min:sec.millisec'
    milli = x % 1000
    x = x // 1000
    sec = x % 60
    x = x // 60
    minu = x % 60
    x = x // 60
    timeString = '%d:%d:%d.%d' % (x, minu, sec, milli)
    return timeString