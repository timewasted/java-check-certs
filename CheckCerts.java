import java.io.IOException;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.TimeZone;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

public class CheckCerts {
    protected int warnYears = 0;
    protected int warnMonths = 0;
    protected int warnDays = 30;

    public static void main(String[] args) {
        // FIXME: Allow for modifying the warning times via command line flags.
        new CheckCerts().CheckHosts(args);
    }

    public void CheckHosts(String[] hosts) {
        for( String host : hosts ) {
            checkHost(host);
        }
    }

    private void checkHost(String host) {
        // Attempt to connect to the host.
        String httpsHost = "https://" + host;
        HttpsURLConnection conn;

        try {
            URL url = new URL(httpsHost);
            conn = (HttpsURLConnection)url.openConnection();
            conn.connect();
        } catch(MalformedURLException e) {
            System.err.printf("Malformed URL '%s'.\n", httpsHost);
            return;
        } catch(SocketTimeoutException e) {
            System.err.printf("Connection to '%s' timed out.\n", httpsHost);
            return;
        } catch(IOException e) {
            System.err.printf("IO error on '%s'.\n", httpsHost);
            return;
        }

        // Read the certificates.
        X509Certificate[] certs;
        TimeZone utc = TimeZone.getTimeZone("UTC");
        Calendar expiresAt = Calendar.getInstance(utc);
        Calendar currentDate = Calendar.getInstance(utc);
        Calendar futureDate = Calendar.getInstance(utc);

        futureDate.add(Calendar.YEAR, warnYears);
        futureDate.add(Calendar.MONTH, warnMonths);
        futureDate.add(Calendar.DAY_OF_MONTH, warnDays);

        try {
            certs = (X509Certificate[])conn.getServerCertificates();
            for( X509Certificate cert : certs ) {
                expiresAt.setTime(cert.getNotAfter());
                if( futureDate.after(expiresAt) ) {
                    // Why is there not an easier/cleaner way to get the common name?
                    LdapName dn = new LdapName(cert.getSubjectX500Principal().getName());
                    String cn = "";
                    for( Rdn rdn : dn.getRdns() ) {
                        if( rdn.getType().equalsIgnoreCase("CN") ) {
                            cn = (String)rdn.getValue();
                            break;
                        }
                    }

                    Long expiresIn = expiresAt.getTimeInMillis() - currentDate.getTimeInMillis();
                    if( expiresIn <= 0 ) {
                        // No dividing by zero for us!
                        System.out.printf("%s: %s is already expired!\n", httpsHost, cn);
                    } else if( expiresIn < 24*60*60*1000 ) {
                        System.out.printf("%s: %s expires in %d hours!\n", httpsHost, cn, expiresIn / (60*60*1000));
                    } else {
                        System.out.printf("%s: %s expires in roughly %d day(s).\n", httpsHost, cn, expiresIn / (24*60*60*1000));
                    }
                }
            }
        } catch(SSLPeerUnverifiedException e) {
            System.err.printf("Peer is not verified on '%s'.\n", httpsHost);
            return;
        } catch(InvalidNameException e) {
            System.err.printf("Invalid distinguished name on '%s'.\n", httpsHost);
            return;
        }
    }
}
