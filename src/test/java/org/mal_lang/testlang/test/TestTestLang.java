package org.mal_lang.testlang.test;

import core.Attacker;
import core.Asset;
import core.AttackStep;
import core.Defense;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public class TestTestLang {
    
    @Test 
    public void testBypassIfInspectionEnabled() {
        Firewall firewall = new Firewall("Firewall1", true, true);
        Network network = new Network();
        network.addFirewalls(firewall);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(firewall.attemptBypassHeaderInspection); 
        attacker.attack();

        network.access.assertUncompromised();

    }

    @Test 
    public void testBypassIfMisconfiguredHeaderInspection() {
        Firewall firewall = new Firewall("Firewall1", false, true);
        Network network = new Network();
        network.addFirewalls(firewall);
        
        Attacker attacker = new Attacker();
        attacker.addAttackPoint(firewall.attemptBypassHeaderInspection); 
        attacker.attack();

        firewall.bypassedHeaderInspection.assertCompromisedInstantaneously();
        firewall.bypassedPayloadInspection.assertUncompromised();
        network.access.assertCompromisedInstantaneously();
    }

    @Test
    public void testBypassByCompromisingManagerSoftware() {
        Firewall firewall = new Firewall("Firewall1", true, true);
        Network network = new Network();
        network.addFirewalls(firewall);

        Attacker attacker = new Attacker();
        attacker.addAttackPoint(firewall.compromiseManagerSoftware);
        attacker.attack();

        network.access.assertCompromisedInstantaneously();
    }

    @Test void testUploadMaliciousFilesToTarget() {
        Firewall firewall = new Firewall("Firewall1", false, false);
        Server databaseServer = new Server();
        Server targetServer = new Server();
        Credentials sshKey = new Credentials();
        databaseServer.addStoredCredentials(sshKey);
        targetServer.addAuthCredentials(sshKey);

        Network network = new Network();
        network.addFirewalls(firewall);
        network.addServers(databaseServer);
        network.addServers(targetServer);


        Attacker attacker = new Attacker();
        attacker.addAttackPoint(firewall.attemptBypassHeaderInspection); 
        attacker.addAttackPoint(firewall.attemptBypassPayloadInspection);
        attacker.addAttackPoint(databaseServer.authenticate);
        attacker.attack();

        firewall.bypassedHeaderInspection.assertCompromisedInstantaneously();
        firewall.bypassedPayloadInspection.assertCompromisedInstantaneously();
        network.access.assertCompromisedInstantaneously();
        databaseServer.connect.assertCompromisedInstantaneously();
        databaseServer.compromise.assertCompromisedInstantaneously();
        sshKey.access.assertCompromisedInstantaneously();
        targetServer.authenticate.assertCompromisedInstantaneously();
        targetServer.uploadMaliciousFiles.assertCompromisedInstantaneously();
    }


    @AfterEach
	public void deleteModel() {
		Asset.allAssets.clear();
		AttackStep.allAttackSteps.clear();
		Defense.allDefenses.clear();
	}
}
