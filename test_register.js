async function test() {
    try {
        const response = await fetch('http://127.0.0.1:5000/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: 'clerktest',
                password: 'password123',
                fullname: 'Test Clerk',
                role: 'cashier'
            })
        });
        const data = await response.json();
        console.log("Response status:", response.status);
        console.log("Response data:", data);
    } catch (err) {
        console.error("Error:", err);
    }
}
test();