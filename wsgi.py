from App import sockio, app, ConsoleLog

if __name__ == '__main__':
    ConsoleLog('Server started successfully')
    try:
        sockio.run(app, host='0.0.0.0')
    except KeyboardInterrupt:
        ConsoleLog('Server shutting down due to keyboard interrupt')
