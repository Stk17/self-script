__author__ = 'arhaxor21'
import sys

reload(sys)
sys.setdefaultencoding('utf-8')
import random
from burp import ITab
from javax.swing import JMenu
from javax.swing import JMenuItem
from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
from burp import IContextMenuFactory
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from java.awt import GridBagLayout, GridBagConstraints
from javax.swing import JLabel, JTextField, JOptionPane, JTabbedPane, JPanel, JButton


class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):


        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("custom-Ip")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.issueAlert("Loaded Successfull.")

       
        self._helpers = callbacks.getHelpers()

        
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        print "[*]Successfull..."

    def createMenuItems(self, invocation):
        self.menus = []
        self.mainMenu = JMenu("custom-Ip")
        self.menus.append(self.mainMenu)
        self.invocation = invocation
        
        menuItem = ['inputIP', '127.0.0.1', 'randomIP']
        for tool in menuItem:
            
            if tool == 'inputIP':
                menu = JMenuItem(tool, None, actionPerformed=lambda x: self.modifyHeader(x))
                self.mainMenu.add(menu)
            elif tool == '127.0.0.1':
                menu = JMenuItem(tool, None, actionPerformed=lambda x: self.modifyHeader(x))
                self.mainMenu.add(menu)
            elif tool == 'randomIP':
                menu = JMenuItem(tool, None, actionPerformed=lambda x: self.modifyHeader(x))
                self.mainMenu.add(menu)

        return self.menus if self.menus else None

    def addIPs(self, ip):

            currentRequest = self.invocation.getSelectedMessages()[0]  
            requestInfo = self._helpers.analyzeRequest(currentRequest)  
            self.headers = list(requestInfo.getHeaders())

            self.headers.append(u'X-Forwarded-For:' + ip)
            self.headers.append(u'X-Forwarded:' + ip)
            self.headers.append(u'Forwarded-For:' + ip)
            self.headers.append(u'Forwarded:' + ip)
            self.headers.append(u'X-Forwarded-Host:' + ip)
            self.headers.append(u'X-remote-IP:' + ip)
            self.headers.append(u'X-remote-addr:' + ip)
            self.headers.append(u'True-Client-IP:' + ip)
            self.headers.append(u'X-Client-IP:' + ip)
            self.headers.append(u'Client-IP:' + ip)
            self.headers.append(u'X-Real-IP:' + ip)
            self.headers.append(u'Ali-CDN-Real-IP:' + ip)
            self.headers.append(u'Cdn-Src-Ip:' + ip)
            self.headers.append(u'Cdn-Real-Ip:' + ip)
            self.headers.append(u'CF-Connecting-IP:' + ip)
            self.headers.append(u'X-Cluster-Client-IP:' + ip)
            self.headers.append(u'WL-Proxy-Client-IP:' + ip)
            self.headers.append(u'Proxy-Client-IP:' + ip)
            self.headers.append(u'Fastly-Client-Ip:' + ip)
            self.headers.append(u'True-Client-Ip:' + ip)



        

            

            bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]  
            self.body = self._helpers.bytesToString(bodyBytes)  
            
            newMessage = self._helpers.buildHttpMessage(self.headers, self.body)
            currentRequest.setRequest(newMessage)  


    def modifyHeader(self, x):
        if x.getSource().text == 'inputIP':  
            ip = JOptionPane.showInputDialog("Pls input ur ip:");

            self.addIPs(ip)
        elif x.getSource().text == '127.0.0.1':
            self.addIPs("127.0.0.1")

        elif x.getSource().text == 'randomIP':

            a = str(int(random.uniform(1, 255)))
            b = str(int(random.uniform(1, 255)))
            c = str(int(random.uniform(1, 255)))
            d = str(int(random.uniform(1, 255)))
            ip = a + "." + b + "." + c + "." + d

            self.addIPs(ip)

    def getGeneratorName(self):
        return "custom-IpPayloads"

    def createNewInstance(self, attack):
        return custom-IpGenerator(self, attack)

class custom-IpGenerator(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payload = 1
        self.num_iterations = 0
        return

    
    def hasMorePayloads(self):
        if self.num_iterations == self.max_payload:
            return False
        else:
            return True

    def getNextPayload(self, current_payload):
        a = str(int(random.uniform(1, 255)))
        b = str(int(random.uniform(1, 255)))
        c = str(int(random.uniform(1, 255)))
        d = str(int(random.uniform(1, 255)))

        payload = a + "." + b + "." + c + "." + d

        return payload
