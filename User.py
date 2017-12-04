#!/usr/bin/env python

"""
This class stores the information of users in a compact way
mod = modular base used in diffie hellman
base = the base that will be used for the exponent in diffie helman
pub = the public key of the user that this object will represent
shared = the shared secret between this user and the user running the 
            program
"""
class User():
    
    def __init__(self, name, modVal, baseVal, pubKey, sharedVal):
        self.userName = name
        self.mod = modVal
        self.base = baseVal
        self.pub = pubKey
        self.shared = sharedVal

    def getName(self):
        return self.userName
    
    def getMod(self):
        return self.mod
    
    def getBase(self):
        return self.base

    def getPub(self):
        return self.pub

    def getShared(self):
        return self.shared

    def setName(self, newName):
        self.userName = newName
        return self.userName
    
    def setMod(self, newMod):
        self.mod = newMod
        return self.mod
    
    def setBase(self, newBase):
        self.base = newBase
        return self.base

    def setPub(self, newPub):
        self.pub = newPub
        return self.pub

    def setShared(self, newShare):
        self.shared = newShare
        return self.shared

